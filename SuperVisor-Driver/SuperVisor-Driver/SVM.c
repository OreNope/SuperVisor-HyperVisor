#include "SVM.h"
#include "Processor.h"
#include "MsrBitmap.h"

UINT64 g_StackPointer;
UINT64 g_BasePointer;
UINT64 g_Cr3TargetCount;
UINT64 g_GuestRSP;
UINT64 g_GuestRIP;

BOOLEAN InitializeSvm()
{
    if (!IsSvmSupported())
    {
        DbgPrint("[*] SVM isn't supported in this machine!");
        return FALSE;
    }

    PSHARED_VIRTUAL_PROCESSOR_DATA  sharedVpData = ExAllocatePoolWithTag(NonPagedPool, sizeof(SHARED_VIRTUAL_PROCESSOR_DATA), POOLTAG);
    RtlZeroMemory(sharedVpData, sizeof(SHARED_VIRTUAL_PROCESSOR_DATA));

    if (!sharedVpData)
        return FALSE;

    PHYSICAL_ADDRESS Highest;
    Highest.QuadPart = ~0ULL;
    sharedVpData->MsrPermissionsMap = MmAllocateContiguousMemory(SVM_MSR_PERMISSIONS_MAP_SIZE, Highest);

    RtlZeroMemory(sharedVpData->MsrPermissionsMap, SVM_MSR_PERMISSIONS_MAP_SIZE);


    if (sharedVpData->MsrPermissionsMap)
    {
        ExFreePoolWithTag(sharedVpData, POOLTAG);
        return FALSE;
    }

    InitializeSLAT(sharedVpData);
    InitializeMsrBitmap(sharedVpData->MsrPermissionsMap);

    // Initialize vmx on each logical processor (_LogicalProcessorIndex is defined inside the macro)
    RunOnEachLogicalProcessor(
    {
        PCONTEXT contextRecord = ExAllocatePoolWithTag(NonPagedPool, sizeof(CONTEXT), POOLTAG);
            
        if (!contextRecord)
        {
            DbgPrint("Insufficient memory.\n");
            goto exit;
        }

        PVIRTUAL_PROCESSOR_DATA vpData = ExAllocatePoolWithTag(NonPagedPool, sizeof(VIRTUAL_PROCESSOR_DATA), POOLTAG);

        RtlZeroMemory(vpData, sizeof(VIRTUAL_PROCESSOR_DATA));

        if (!vpData)
        {
            DbgPrint("Insufficient memory.\n");
            goto exit;
        }

        // captured state is used as an initial state of the guest mode
        RtlCaptureContext(contextRecord);

        // Enable SVM by setting EFER.SVME
        __writemsr(IA32_MSR_EFER, __readmsr(IA32_MSR_EFER) | EFER_SVME);
        DbgPrint("[*] SVM Enabled Successfully!");

        PrepareForVirtualization(VpData, SharedVpData, ContextRecord);

        AllocateVmxonRegion(g_GuestState + _LogicalProcessorIndex);
        AllocateVmcsRegion(g_GuestState + _LogicalProcessorIndex);

        DbgPrint("[*] VMCS Region is allocated at  ===============> %llx", g_GuestState[_LogicalProcessorIndex].VmcsRegion);
        DbgPrint("[*] VMXON Region is allocated at ===============> %llx", g_GuestState[_LogicalProcessorIndex].VmxonRegion);

    exit:

    });
}

void PrepareForVirtualization(_Inout_ PVIRTUAL_PROCESSOR_DATA VpData, _In_ PSHARED_VIRTUAL_PROCESSOR_DATA SharedVpData, _In_ const CONTEXT* ContextRecord)
{
    DESCRIPTOR_TABLE_REGISTER gdtr, idtr;
    UINT64 guestVmcbPa, hostVmcbPa, hostStateAreaPa, pml4BasePa, msrpmPa;

    // Capture the current GDTR and IDTR to use as initial values of the guest mode.
    _sgdt(&gdtr);
    __sidt(&idtr);

    guestVmcbPa = VirtualToPhysicalAddress(&VpData->GuestVmcb);
    hostVmcbPa = VirtualToPhysicalAddress(&VpData->HostVmcb);
    hostStateAreaPa = VirtualToPhysicalAddress(&VpData->HostStateArea);
    pml4BasePa = VirtualToPhysicalAddress(&SharedVpData->Pml4Entries);
    msrpmPa = VirtualToPhysicalAddress(SharedVpData->MsrPermissionsMap);

    // Configure to trigger #VMEXIT with CPUID and VMRUN instructions. CPUID is
    // intercepted to present existence of the hypervisor and provide
    // an interface to ask it to unload itself.
    VpData->GuestVmcb.ControlArea.InterceptMisc1 |= SVM_INTERCEPT_MISC1_CPUID;
    VpData->GuestVmcb.ControlArea.InterceptMisc2 |= SVM_INTERCEPT_MISC2_VMRUN;

    // Also, configure to trigger #VMEXIT on MSR access as configured by the
    // MSRPM. In our case, write to IA32_MSR_EFER is intercepted.
    VpData->GuestVmcb.ControlArea.InterceptMisc1 |= SVM_INTERCEPT_MISC1_MSR_PROT;
    VpData->GuestVmcb.ControlArea.MsrpmBasePa = msrpmPa;

    // Specify guest's address space ID (ASID). TLB is maintained by the ID for
    // guests. Use the same value for all processors since all of them run a
    // single guest in our case.
    VpData->GuestVmcb.ControlArea.GuestAsid = 1;

    // Enable Nested Page Tables. By enabling this, the processor performs the
    // nested page walk, that involves with an additional page walk to translate
    // a guest physical address to a system physical address. An address of
    // nested page tables is specified by the NCr3 field of VMCB.
    
    // Note that our hypervisor does not trigger any additional #VMEXIT due to
    // the use of Nested Page Tables since all physical addresses from 0-512 GB
    // are configured to be accessible from the guest.
    VpData->GuestVmcb.ControlArea.NpEnable |= SVM_NP_ENABLE_NP_ENABLE;
    VpData->GuestVmcb.ControlArea.NCr3 = pml4BasePa;

    // Set up the initial guest state based on the current system state. Those
    // values are loaded into the processor as guest state when the VMRUN
    // instruction is executed.
    VpData->GuestVmcb.StateSaveArea.GdtrBase = gdtr.Base;
    VpData->GuestVmcb.StateSaveArea.GdtrLimit = gdtr.Limit;
    VpData->GuestVmcb.StateSaveArea.IdtrBase = idtr.Base;
    VpData->GuestVmcb.StateSaveArea.IdtrLimit = idtr.Limit;
    
    VpData->GuestVmcb.StateSaveArea.CsLimit = GetSegmentLimit(ContextRecord->SegCs);
    VpData->GuestVmcb.StateSaveArea.DsLimit = GetSegmentLimit(ContextRecord->SegDs);
    VpData->GuestVmcb.StateSaveArea.EsLimit = GetSegmentLimit(ContextRecord->SegEs);
    VpData->GuestVmcb.StateSaveArea.SsLimit = GetSegmentLimit(ContextRecord->SegSs);
    VpData->GuestVmcb.StateSaveArea.CsSelector = ContextRecord->SegCs;
    VpData->GuestVmcb.StateSaveArea.DsSelector = ContextRecord->SegDs;
    VpData->GuestVmcb.StateSaveArea.EsSelector = ContextRecord->SegEs;
    VpData->GuestVmcb.StateSaveArea.SsSelector = ContextRecord->SegSs;
    VpData->GuestVmcb.StateSaveArea.CsAttrib = GetSegmentAccessRight(ContextRecord->SegCs, gdtr.Base);
    VpData->GuestVmcb.StateSaveArea.DsAttrib = GetSegmentAccessRight(ContextRecord->SegDs, gdtr.Base);
    VpData->GuestVmcb.StateSaveArea.EsAttrib = GetSegmentAccessRight(ContextRecord->SegEs, gdtr.Base);
    VpData->GuestVmcb.StateSaveArea.SsAttrib = GetSegmentAccessRight(ContextRecord->SegSs, gdtr.Base);

    VpData->GuestVmcb.StateSaveArea.Efer = __readmsr(IA32_MSR_EFER);
    VpData->GuestVmcb.StateSaveArea.Cr0 = __readcr0();
    VpData->GuestVmcb.StateSaveArea.Cr2 = __readcr2();
    VpData->GuestVmcb.StateSaveArea.Cr3 = __readcr3();
    VpData->GuestVmcb.StateSaveArea.Cr4 = __readcr4();
    VpData->GuestVmcb.StateSaveArea.Rflags = ContextRecord->EFlags;
    VpData->GuestVmcb.StateSaveArea.Rsp = ContextRecord->Rsp;
    VpData->GuestVmcb.StateSaveArea.Rip = ContextRecord->Rip;
    VpData->GuestVmcb.StateSaveArea.GPat = __readmsr(IA32_MSR_PAT);

    // Save some of the current state on VMCB. Some of those states are:
    // - FS, GS, TR, LDTR (including all hidden state)
    // - KernelGsBase
    // - STAR, LSTAR, CSTAR, SFMASK
    // - SYSENTER_CS, SYSENTER_ESP, SYSENTER_EIP
    
    // Those are restored to the processor right before #VMEXIT with the VMLOAD
    // instruction so that the guest can start its execution with saved state,
    // and also, re-saved to the VMCS with right after #VMEXIT with the VMSAVE
    // instruction so that the host (hypervisor) do not destroy guest's state.
    __svm_vmsave(guestVmcbPa);

    // Store data to stack so that the host (hypervisor) can use those values.
    VpData->HostStackLayout.Reserved1 = MAXUINT64;
    VpData->HostStackLayout.SharedVpData = SharedVpData;
    VpData->HostStackLayout.Self = VpData;
    VpData->HostStackLayout.HostVmcbPa = hostVmcbPa;
    VpData->HostStackLayout.GuestVmcbPa = guestVmcbPa;

    // Set an address of the host state area to VM_HSAVE_PA MSR. The processor
    // saves some of the current state on VMRUN and loads them on #VMEXIT. See
    __writemsr(SVM_MSR_VM_HSAVE_PA, hostStateAreaPa);

    // Also, save some of the current state to VMCB for the host. This is loaded
    // after #VMEXIT to reproduce the current state for the host (hypervisor).
    __svm_vmsave(hostVmcbPa);
}

UINT16 GetSegmentAccessRight(_In_ UINT16 SegmentSelector, _In_ ULONG_PTR GdtBase)
{
    PSEGMENT_DESCRIPTOR descriptor;
    SEGMENT_ATTRIBUTE attribute;

    // Get a segment descriptor corresponds to the specified segment selector.
    descriptor = (PSEGMENT_DESCRIPTOR)(GdtBase + (SegmentSelector & ~RPL_MASK));

    attribute.Fields.Type = descriptor->Fields.Type;
    attribute.Fields.System = descriptor->Fields.System;
    attribute.Fields.Dpl = descriptor->Fields.Dpl;
    attribute.Fields.Present = descriptor->Fields.Present;
    attribute.Fields.Avl = descriptor->Fields.Avl;
    attribute.Fields.LongMode = descriptor->Fields.LongMode;
    attribute.Fields.DefaultBit = descriptor->Fields.DefaultBit;
    attribute.Fields.Granularity = descriptor->Fields.Granularity;
    attribute.Fields.Reserved1 = 0;

    return attribute.AsUInt16;
}

void TerminateVmx()
{
	DbgPrint("\n[*] Terminating VMX...\n");

    // Terminate vmx on each logical processor (_LogicalProcessorIndex is defined inside the macro)
    RunOnEachLogicalProcessor(
    {
        KIRQL OldIrql = KeRaiseIrqlToDpcLevel();

        __vmx_off();

        KeLowerIrql(OldIrql);
        KeRevertToUserAffinityThread();

        ExFreePoolWithTag(PhysicalToVirtualAddress(g_GuestState[_LogicalProcessorIndex].VmxonRegion), POOLTAG);
        ExFreePoolWithTag(PhysicalToVirtualAddress(g_GuestState[_LogicalProcessorIndex].VmcsRegion), POOLTAG);
        ExFreePoolWithTag(PhysicalToVirtualAddress(g_GuestState[_LogicalProcessorIndex].VmmStack), POOLTAG);
        ExFreePoolWithTag(PhysicalToVirtualAddress(g_GuestState[_LogicalProcessorIndex].MsrBitmap), POOLTAG);
    });

    DbgPrint("[*] VMX Operation turned off successfully!\n");
}

void VirtualizeCurrentSystem(ULONG ProcessorID, PEPTP EPTP, PVOID GuestStack)
{
    DbgPrint("\n======================== Launching VM =============================\n");

    KAFFINITY AffinityMask;
    AffinityMask = 1LL << ProcessorID;
    KeSetSystemAffinityThread(AffinityMask);

    DbgPrint("============= Executing in %uth logical processor =============", ProcessorID + 1);


    // Clear the VMCS State
    if (!ClearVmcsState(&g_GuestState[ProcessorID]))
    {
        DbgPrint("[*] Fail to clear VMCS state!\n");
        return FALSE;
    }

    // Load VMCS (Set the Current VMCS)
    if (!LoadVmcs(&g_GuestState[ProcessorID]))
    {
        DbgPrint("[*] Fail to load VMCS!\n");
        return FALSE;
    }

    DbgPrint("[*] Setting up VMCS.\n");
    SetupVmcsAndVirtualizeMachine(&g_GuestState[ProcessorID], EPTP, GuestStack);

    DbgPrint("[*] Executing VMLANUNCH.\n");

    AsmSaveStateForVmxoff();

    __vmx_vmlaunch();

    // this code runs only if vmlaunch failed!
    ULONG64 ErrorCode = 0;
    __vmx_vmread(VM_INSTRUCTION_ERROR, &ErrorCode);
    __vmx_off();
    DbgPrint("[*] VMLAUNCH Error: 0x%llx\n", ErrorCode);
    DbgBreakPoint();

    return TRUE;
}

BOOLEAN SetupVmcsAndVirtualizeMachine(VIRTUAL_MACHINE_STATE* GuestState, PEPTP EPTP, PVOID GuestStack)
{
    BOOLEAN Status = FALSE;

    // & 0xF8 is because Intel mentioned that the three less significant bits must be cleared
    __vmx_vmwrite(HOST_ES_SELECTOR, GetEs() & 0xf8);
    __vmx_vmwrite(HOST_CS_SELECTOR, GetCs() & 0xf8);
    __vmx_vmwrite(HOST_SS_SELECTOR, GetSs() & 0xf8);
    __vmx_vmwrite(HOST_DS_SELECTOR, GetDs() & 0xf8);
    __vmx_vmwrite(HOST_FS_SELECTOR, GetFs() & 0xf8);
    __vmx_vmwrite(HOST_GS_SELECTOR, GetGs() & 0xf8);
    __vmx_vmwrite(HOST_TR_SELECTOR, GetTr() & 0xf8);

    // Setting the link pointer to the required value for 4KB VMCS
    __vmx_vmwrite(VMCS_LINK_POINTER, ~0ULL);

    __vmx_vmwrite(GUEST_IA32_DEBUGCTL, __readmsr(MSR_IA32_DEBUGCTL) & (~0L));
    __vmx_vmwrite(GUEST_IA32_DEBUGCTL_HIGH, __readmsr(MSR_IA32_DEBUGCTL) >> 32);

    // Time-stamp counter
    __vmx_vmwrite(TSC_OFFSET, 0);
    __vmx_vmwrite(TSC_OFFSET_HIGH, 0);

    __vmx_vmwrite(PAGE_FAULT_ERROR_CODE_MASK, 0);
    __vmx_vmwrite(PAGE_FAULT_ERROR_CODE_MATCH, 0);

    __vmx_vmwrite(VM_EXIT_MSR_STORE_COUNT, 0);
    __vmx_vmwrite(VM_EXIT_MSR_LOAD_COUNT, 0);

    __vmx_vmwrite(VM_ENTRY_MSR_LOAD_COUNT, 0);
    __vmx_vmwrite(VM_ENTRY_INTR_INFO_FIELD, 0);

    ULONG64 GdtBase = GetGdtBase();

    FillGuestSelectorData((PVOID)GdtBase, ES, GetEs());
    FillGuestSelectorData((PVOID)GdtBase, CS, GetCs());
    FillGuestSelectorData((PVOID)GdtBase, SS, GetSs());
    FillGuestSelectorData((PVOID)GdtBase, DS, GetDs());
    FillGuestSelectorData((PVOID)GdtBase, FS, GetFs());
    FillGuestSelectorData((PVOID)GdtBase, GS, GetGs());
    FillGuestSelectorData((PVOID)GdtBase, LDTR, GetLdtr());
    FillGuestSelectorData((PVOID)GdtBase, TR, GetTr());

    __vmx_vmwrite(GUEST_FS_BASE, __readmsr(MSR_FS_BASE));
    __vmx_vmwrite(GUEST_GS_BASE, __readmsr(MSR_GS_BASE));

    __vmx_vmwrite(GUEST_INTERRUPTIBILITY_INFO, 0);
    __vmx_vmwrite(GUEST_ACTIVITY_STATE, 0);

    DbgPrint("[*] MSR_IA32_VMX_PROCBASED_CTLS : 0x%llx\n", AdjustControls(CPU_BASED_ACTIVATE_MSR_BITMAP | CPU_BASED_ACTIVATE_SECONDARY_CONTROLS, MSR_IA32_VMX_PROCBASED_CTLS));
    DbgPrint("[*] MSR_IA32_VMX_PROCBASED_CTLS2 : 0x%llx\n", AdjustControls(CPU_BASED_CTL2_RDTSCP | CPU_BASED_CTL2_ENABLE_INVPCID | CPU_BASED_CTL2_ENABLE_XSAVE_XRSTORS, MSR_IA32_VMX_PROCBASED_CTLS2));

    __vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL, AdjustControls(CPU_BASED_ACTIVATE_MSR_BITMAP | CPU_BASED_ACTIVATE_SECONDARY_CONTROLS, MSR_IA32_VMX_PROCBASED_CTLS));
    __vmx_vmwrite(SECONDARY_VM_EXEC_CONTROL, AdjustControls(CPU_BASED_CTL2_RDTSCP | CPU_BASED_CTL2_ENABLE_INVPCID | CPU_BASED_CTL2_ENABLE_XSAVE_XRSTORS, MSR_IA32_VMX_PROCBASED_CTLS2));

    __vmx_vmwrite(PIN_BASED_VM_EXEC_CONTROL, AdjustControls(0, MSR_IA32_VMX_PINBASED_CTLS));
    __vmx_vmwrite(VM_EXIT_CONTROLS, AdjustControls(VM_EXIT_IA32E_MODE | VM_EXIT_ACK_INTR_ON_EXIT, MSR_IA32_VMX_EXIT_CTLS));
    __vmx_vmwrite(VM_ENTRY_CONTROLS, AdjustControls(VM_ENTRY_IA32E_MODE, MSR_IA32_VMX_ENTRY_CTLS));

    __vmx_vmwrite(CR3_TARGET_COUNT, 0);
    __vmx_vmwrite(CR3_TARGET_VALUE0, 0);
    __vmx_vmwrite(CR3_TARGET_VALUE1, 0);
    __vmx_vmwrite(CR3_TARGET_VALUE2, 0);
    __vmx_vmwrite(CR3_TARGET_VALUE3, 0);

    __vmx_vmwrite(CR0_GUEST_HOST_MASK, 0);
    __vmx_vmwrite(CR4_GUEST_HOST_MASK, 0);
    __vmx_vmwrite(CR0_READ_SHADOW, 0);
    __vmx_vmwrite(CR4_READ_SHADOW, 0);

    __vmx_vmwrite(GUEST_CR0, __readcr0());
    __vmx_vmwrite(GUEST_CR3, __readcr3());
    __vmx_vmwrite(GUEST_CR4, __readcr4());

    __vmx_vmwrite(HOST_CR0, __readcr0());
    __vmx_vmwrite(HOST_CR3, __readcr3());
    __vmx_vmwrite(HOST_CR4, __readcr4());

    __vmx_vmwrite(GUEST_GDTR_BASE, GetGdtBase());
    __vmx_vmwrite(GUEST_IDTR_BASE, GetIdtBase());
    __vmx_vmwrite(GUEST_GDTR_LIMIT, GetGdtLimit());
    __vmx_vmwrite(GUEST_IDTR_LIMIT, GetIdtLimit());

    __vmx_vmwrite(GUEST_RFLAGS, GetRflags());

    __vmx_vmwrite(GUEST_SYSENTER_CS, __readmsr(MSR_IA32_SYSENTER_CS));
    __vmx_vmwrite(GUEST_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP));
    __vmx_vmwrite(GUEST_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));
    __vmx_vmwrite(HOST_IA32_SYSENTER_CS, __readmsr(MSR_IA32_SYSENTER_CS));
    __vmx_vmwrite(HOST_IA32_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP));
    __vmx_vmwrite(HOST_IA32_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));

    SEGMENT_SELECTOR SegmentSelector = { 0 };

    GetSegmentDescriptor(&SegmentSelector, GetTr(), (PUCHAR)GetGdtBase());
    __vmx_vmwrite(HOST_TR_BASE, SegmentSelector.BASE);

    __vmx_vmwrite(HOST_FS_BASE, __readmsr(MSR_FS_BASE));
    __vmx_vmwrite(HOST_GS_BASE, __readmsr(MSR_GS_BASE));

    __vmx_vmwrite(HOST_GDTR_BASE, GetGdtBase());
    __vmx_vmwrite(HOST_IDTR_BASE, GetIdtBase());

    __vmx_vmwrite(GUEST_RSP, GuestStack); // setup guest sp
    __vmx_vmwrite(GUEST_RIP, VmxRestoreState); // setup guest ip

    __vmx_vmwrite(HOST_RSP, ((ULONG64)GuestState->VmmStack + VMM_STACK_SIZE - 1));
    __vmx_vmwrite(HOST_RIP, (ULONG64)AsmVmexitHandler);
}

BOOLEAN SetTargetControls(UINT64 CR3, UINT64 Index)
{
    //
    // Index starts from 0 , not 1
    //
    if (Index >= 4)
    {
        //
        // Not supported for more than 4 , at least for now :(
        //
        return FALSE;
    }

    UINT64 temp = 0;

    if (CR3 == 0)
    {
        if (g_Cr3TargetCount <= 0)
        {
            //
            // Invalid command as g_Cr3TargetCount cannot be less than zero
            // s
            return FALSE;
        }
        else
        {
            g_Cr3TargetCount -= 1;
            if (Index == 0)
            {
                __vmx_vmwrite(CR3_TARGET_VALUE0, 0);
            }
            if (Index == 1)
            {
                __vmx_vmwrite(CR3_TARGET_VALUE1, 0);
            }
            if (Index == 2)
            {
                __vmx_vmwrite(CR3_TARGET_VALUE2, 0);
            }
            if (Index == 3)
            {
                __vmx_vmwrite(CR3_TARGET_VALUE3, 0);
            }
        }
    }
    else
    {
        if (Index == 0)
        {
            __vmx_vmwrite(CR3_TARGET_VALUE0, CR3);
        }
        if (Index == 1)
        {
            __vmx_vmwrite(CR3_TARGET_VALUE1, CR3);
        }
        if (Index == 2)
        {
            __vmx_vmwrite(CR3_TARGET_VALUE2, CR3);
        }
        if (Index == 3)
        {
            __vmx_vmwrite(CR3_TARGET_VALUE3, CR3);
        }
        g_Cr3TargetCount += 1;
    }

    __vmx_vmwrite(CR3_TARGET_COUNT, g_Cr3TargetCount);
    return TRUE;
}

VOID MainVmexitHandler(PGUEST_REGS GuestRegs)
{
    BOOLEAN Status = FALSE;

    ULONG ExitReason = 0;
    __vmx_vmread(VM_EXIT_REASON, &ExitReason);

    ULONG ExitQualification = 0;
    __vmx_vmread(EXIT_QUALIFICATION, &ExitQualification);
    ExitReason &= 0xffff;

    switch (ExitReason)
    {
    case EXIT_REASON_TRIPLE_FAULT:
    {
        //	DbgBreakPoint();
        break;
    }

    //
    // 25.1.2  Instructions That Cause VM Exits Unconditionally
    // The following instructions cause VM exits when they are executed in VMX non-root operation: CPUID, GETSEC,
    // INVD, and XSETBV. This is also true of instructions introduced with VMX, which include: INVEPT, INVVPID,
    // VMCALL, VMCLEAR, VMLAUNCH, VMPTRLD, VMPTRST, VMRESUME, VMXOFF, and VMXON.
    //
    case EXIT_REASON_VMCLEAR:
    case EXIT_REASON_VMPTRLD:
    case EXIT_REASON_VMPTRST:
    case EXIT_REASON_VMREAD:
    case EXIT_REASON_VMRESUME:
    case EXIT_REASON_VMWRITE:
    case EXIT_REASON_VMXOFF:
    case EXIT_REASON_VMXON:
    case EXIT_REASON_VMLAUNCH:
    {
        // DbgBreakPoint();

        ULONG RFLAGS = 0;
        __vmx_vmread(GUEST_RFLAGS, &RFLAGS);
        __vmx_vmwrite(GUEST_RFLAGS, RFLAGS | 0x1); // cf=1 indicate vm instructions fail
        break;
    }

    case EXIT_REASON_CR_ACCESS:
    {
        HandleControlRegisterAccess(GuestRegs);

        break;
    }
    case EXIT_REASON_MSR_READ:
    {
        ULONG ECX = GuestRegs->rcx & 0xffffffff;

        // DbgPrint("[*] RDMSR (based on bitmap) : 0x%llx\n", ECX);
        HandleMSRRead(GuestRegs);

        break;
    }
    case EXIT_REASON_MSR_LOADING:
    {
        break;
    }
    case EXIT_REASON_MSR_WRITE:
    {
        ULONG ECX = GuestRegs->rcx & 0xffffffff;

        HandleMSRWrite(GuestRegs);

        break;
    }
    case EXIT_REASON_CPUID:
    {
        Status = HandleCPUID(GuestRegs); // Detect whether we have to turn off VMX or Not
        if (Status)
        {
            // We have to save GUEST_RIP & GUEST_RSP somewhere to restore them directly

            ULONG ExitInstructionLength = 0;
            g_GuestRIP = 0;
            g_GuestRSP = 0;
            __vmx_vmread(GUEST_RIP, &g_GuestRIP);
            __vmx_vmread(GUEST_RSP, &g_GuestRSP);
            __vmx_vmread(VM_EXIT_INSTRUCTION_LEN, &ExitInstructionLength);

            g_GuestRIP += ExitInstructionLength;
        }
        break;
    }
    case EXIT_REASON_EXCEPTION_NMI:
    {
        // HandleExceptionNMI();
        break;
    }
    case EXIT_REASON_IO_INSTRUCTION:
    {
        UINT64 RIP = 0;
        __vmx_vmread(GUEST_RIP, &RIP);

        // DbgPrint("[*] RIP executed IO instruction : 0x%llx\n", RIP);
        // DbgBreakPoint();

        break;
    }
    default:
    {
        break;
    }
    }
    if (!Status)
    {
        GuestSkipToNextInstruction();
    }

    return Status;
}

BOOLEAN HandleCPUID(PGUEST_REGS state)
{
    INT32 CpuInfo[4];
    ULONG Mode = 0;

    //
    // Check for the magic CPUID sequence, and check that it is coming from
    // Ring 0. Technically we could also check the RIP and see if this falls
    // in the expected function, but we may want to allow a separate "unload"
    // driver or code at some point
    //

    __vmx_vmread(GUEST_CS_SELECTOR, &Mode);
    Mode = Mode & RPL_MASK;

    if ((state->rax == 0x41414141) && (state->rcx == 0x42424242) && Mode == DPL_SYSTEM)
    {
        return TRUE; // Indicates we have to turn off VMX
    }

    //
    // Otherwise, issue the CPUID to the logical processor based on the indexes
    // on the VP's GPRs
    //
    __cpuidex(CpuInfo, (INT32)state->rax, (INT32)state->rcx);

    //
    // Check if this was CPUID 1h, which is the features request
    //
    if (state->rax == 1)
    {
        //
        // Set the Hypervisor Present-bit in RCX, which Intel and AMD have both
        // reserved for this indication
        //
        CpuInfo[2] |= HYPERV_HYPERVISOR_PRESENT_BIT;
    }

    else if (state->rax == HYPERV_CPUID_INTERFACE)
    {
        //
        // Return our interface identifier
        //
        CpuInfo[0] = 'Supe';
        CpuInfo[1] = 'rVis';
        CpuInfo[2] = 'or';

        // SuperVisor
    }

    //
    // Copy the values from the logical processor registers into the VP GPRs
    //
    state->rax = CpuInfo[0];
    state->rbx = CpuInfo[1];
    state->rcx = CpuInfo[2];
    state->rdx = CpuInfo[3];

    return FALSE; // Indicates we don't have to turn off VMX
}

VOID HandleControlRegisterAccess(PGUEST_REGS GuestState)
{
    ULONG ExitQualification = 0;

    __vmx_vmread(EXIT_QUALIFICATION, &ExitQualification);

    PMOV_CR_QUALIFICATION data = (PMOV_CR_QUALIFICATION)&ExitQualification;

    PULONG64 RegPtr = (PULONG64)&GuestState->rax + data->Fields.Register;

    //
    // Because its RSP and as we didn't save RSP correctly (because of pushes)
    // so we have to make it points to the GUEST_RSP
    //
    if (data->Fields.Register == 4)
    {
        INT64 RSP = 0;
        __vmx_vmread(GUEST_RSP, &RSP);
        *RegPtr = RSP;
    }

    switch (data->Fields.AccessType)
    {
    case TYPE_MOV_TO_CR:
    {
        switch (data->Fields.ControlRegister)
        {
        case 0:
            __vmx_vmwrite(GUEST_CR0, *RegPtr);
            __vmx_vmwrite(CR0_READ_SHADOW, *RegPtr);
            break;
        case 3:

            __vmx_vmwrite(GUEST_CR3, (*RegPtr & ~(1ULL << 63)));

            // In the case of using EPT, the context of EPT/VPID should be invalidated
            break;
        case 4:
            __vmx_vmwrite(GUEST_CR4, *RegPtr);
            __vmx_vmwrite(CR4_READ_SHADOW, *RegPtr);
            break;
        default:
            DbgPrint("[*] Unsupported register %d\n", data->Fields.ControlRegister);
            break;
        }
    }
    break;

    case TYPE_MOV_FROM_CR:
    {
        switch (data->Fields.ControlRegister)
        {
        case 0:
            __vmx_vmread(GUEST_CR0, RegPtr);
            break;
        case 3:
            __vmx_vmread(GUEST_CR3, RegPtr);
            break;
        case 4:
            __vmx_vmread(GUEST_CR4, RegPtr);
            break;
        default:
            DbgPrint("[*] Unsupported register %d\n", data->Fields.ControlRegister);
            break;
        }
    }
    break;

    default:
        DbgPrint("[*] Unsupported operation %d\n", data->Fields.AccessType);
        break;
    }
}

VOID HandleMSRRead(PGUEST_REGS GuestRegs)
{
    MSR msr = { 0 };

    //
    // RDMSR. The RDMSR instruction causes a VM exit if any of the following are true:
    // The "use MSR bitmaps" VM-execution control is 0.
    // The value of ECX is not in the ranges 00000000H - 00001FFFH and C0000000H - C0001FFFH
    // The value of ECX is in the range 00000000H - 00001FFFH and bit n in read bitmap for low MSRs is 1,
    //   where n is the value of ECX.
    // The value of ECX is in the range C0000000H - C0001FFFH and bit n in read bitmap for high MSRs is 1,
    //   where n is the value of ECX & 00001FFFH.
    //

    if (((GuestRegs->rcx <= 0x00001FFF)) || ((0xC0000000 <= GuestRegs->rcx) && (GuestRegs->rcx <= 0xC0001FFF)))
    {
        msr.Content = MSRRead((ULONG)GuestRegs->rcx);
    }
    else
    {
        msr.Content = 0;
    }

    GuestRegs->rax = msr.Fields.Low;
    GuestRegs->rdx = msr.Fields.High;
}

VOID HandleMSRWrite(PGUEST_REGS GuestRegs)
{
    MSR msr = { 0 };

    // Check for the sanity of MSR
    if ((GuestRegs->rcx <= 0x00001FFF) || ((0xC0000000 <= GuestRegs->rcx) && (GuestRegs->rcx <= 0xC0001FFF)))
    {
        msr.Fields.Low = (ULONG)GuestRegs->rax;
        msr.Fields.High = (ULONG)GuestRegs->rdx;
        MSRWrite((ULONG)GuestRegs->rcx, msr.Content);
    }
}

VOID SetBit(PVOID Addr, UINT64 Bit, BOOLEAN Set)
{
    PAGED_CODE();

    UINT64 Byte = Bit / 8;
    UINT64 Temp = Bit % 8;
    UINT64 N = 7 - Temp;

    BYTE* Addr2 = Addr;
    if (Set)
    {
        Addr2[Byte] |= (1 << N);
    }
    else
    {
        Addr2[Byte] &= ~(1 << N);
    }
}

VOID GetBit(PVOID Addr, UINT64 Bit)
{
    UINT64 Byte = 0, K = 0;
    Byte = Bit / 8;
    K = 7 - Bit % 8;
    BYTE* Addr2 = Addr;

    return Addr2[Byte] & (1 << K);
}

BOOLEAN SetMsrBitmap(ULONG64 Msr, int ProcessID, BOOLEAN ReadDetection, BOOLEAN WriteDetection)
{
    if (!ReadDetection && !WriteDetection)
    {
        // Invalid Command
        return FALSE;
    }

    if (Msr <= 0x00001FFF)
    {
        if (ReadDetection)
        {
            SetBit(g_GuestState[ProcessID].MsrBitmap, Msr, TRUE);
        }
        if (WriteDetection)
        {
            SetBit(g_GuestState[ProcessID].MsrBitmap + 2048, Msr, TRUE);
        }
    }
    else if ((0xC0000000 <= Msr) && (Msr <= 0xC0001FFF))
    {
        if (ReadDetection)
        {
            SetBit(g_GuestState[ProcessID].MsrBitmap + 1024, Msr - 0xC0000000, TRUE);
        }
        if (WriteDetection)
        {
            SetBit(g_GuestState[ProcessID].MsrBitmap + 3072, Msr - 0xC0000000, TRUE);
        }
    }
    else
    {
        return FALSE;
    }
    return TRUE;
}

VOID VmResumeInstruction()
{
    __vmx_vmresume();

    // if VMRESUME succeeds will never be here !

    ULONG64 ErrorCode = 0;
    __vmx_vmread(VM_INSTRUCTION_ERROR, &ErrorCode);
    __vmx_off();
    DbgPrint("[*] VMRESUME Error : 0x%llx\n", ErrorCode);

    // It's such a bad error because we don't where to go!
    // prefer to break
    DbgBreakPoint();
}

VOID GuestSkipToNextInstruction()
{
    PVOID ResumeRIP = NULL;
    PVOID CurrentRIP = NULL;
    ULONG ExitInstructionLength = 0;

    __vmx_vmread(GUEST_RIP, &CurrentRIP);
    __vmx_vmread(VM_EXIT_INSTRUCTION_LEN, &ExitInstructionLength);

    ResumeRIP = (PCHAR)CurrentRIP + ExitInstructionLength;

    __vmx_vmwrite(GUEST_RIP, (ULONG64)ResumeRIP);
}

void FillGuestSelectorData(PVOID GdtBase, ULONG Segreg, USHORT Selector)
{
    SEGMENT_SELECTOR SegmentSelector = { 0 };
    ULONG AccessRights = 0;

    GetSegmentDescriptor(&SegmentSelector, Selector, GdtBase);
    AccessRights = ((PUCHAR)&SegmentSelector.ATTRIBUTES)[0] + (((PUCHAR)&SegmentSelector.ATTRIBUTES)[1] << 12);

    if (!Selector)
        AccessRights |= 0x10000;

    __vmx_vmwrite(GUEST_ES_SELECTOR + Segreg * 2, Selector);
    __vmx_vmwrite(GUEST_ES_LIMIT + Segreg * 2, SegmentSelector.LIMIT);
    __vmx_vmwrite(GUEST_ES_AR_BYTES + Segreg * 2, AccessRights);
    __vmx_vmwrite(GUEST_ES_BASE + Segreg * 2, SegmentSelector.BASE);
}

BOOLEAN GetSegmentDescriptor(PSEGMENT_SELECTOR SegmentSelector, USHORT Selector, PUCHAR GdtBase)
{
    PSEGMENT_DESCRIPTOR SegDesc = NULL;

    if (!SegmentSelector || Selector & 0x4)
        return FALSE;

    SegDesc = (PSEGMENT_DESCRIPTOR)((PUCHAR)GdtBase + (Selector & ~0x7));

    SegmentSelector->SEL = Selector;
    SegmentSelector->BASE = SegDesc->BASE0 | SegDesc->BASE1 << 16 | SegDesc->BASE2 << 24;
    SegmentSelector->LIMIT = SegDesc->LIMIT0 | (SegDesc->LIMIT1ATTR1 & 0xf) << 16;
    SegmentSelector->ATTRIBUTES.UCHARs = SegDesc->ATTR0 | (SegDesc->LIMIT1ATTR1 & 0xf0) << 4;

    if (!(SegDesc->ATTR0 & 0x10))
    { // LA_ACCESSED
        ULONG64 Tmp;
        // this is a TSS or callgate etc, save the base high part
        Tmp = (*(PULONG64)((PUCHAR)SegDesc + 8));
        SegmentSelector->BASE = (SegmentSelector->BASE & 0xffffffff) | (Tmp << 32);
    }

    if (SegmentSelector->ATTRIBUTES.Fields.G)
    {
        // 4096-bit granularity is enabled for this segment, scale the limit
        SegmentSelector->LIMIT = (SegmentSelector->LIMIT << 12) + 0xfff;
    }

    return TRUE;
}

ULONG AdjustControls(ULONG Ctl, ULONG Msr)
{
    MSR MsrValue = { 0 };

    MsrValue.Content = __readmsr(Msr);
    Ctl &= MsrValue.Fields.High; /* bit == 0 in high word ==> must be zero */
    Ctl |= MsrValue.Fields.Low;  /* bit == 1 in low word  ==> must be one  */
    return Ctl;
}

UINT64 VmptrstInstruction()
{
    UINT64 VmcsPa;

    __vmx_vmptrst(&VmcsPa);

    DbgPrint("[*] VMPTRST %llx\n", VmcsPa);

    return VmcsPa;
}

BOOLEAN ClearVmcsState(VIRTUAL_MACHINE_STATE* GuestState)
{
    int Status = __vmx_vmclear(&GuestState->VmcsRegion);

    DbgPrint("[*] VMCS VMCLEAR Status is: %d\n", Status);

    if (Status)
    {
        DbgPrint("[*] VMCS failed to clear with status: %d\n", Status);
        __vmx_off();
        return FALSE;
    }

    return TRUE;
}

BOOLEAN LoadVmcs(VIRTUAL_MACHINE_STATE* GuestState)
{
    int Status = __vmx_vmptrld(&GuestState->VmcsRegion);

    DbgPrint("[*] VMCS VMPTRLD Status is: %d\n", Status);

    if (Status)
    {
        DbgPrint("[*] VMCS failed with status: %d\n", Status);
        return FALSE;
    }

    return TRUE;
}

