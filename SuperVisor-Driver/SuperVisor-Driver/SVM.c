#include "SVM.h"
#include "Processor.h"
#include "MsrBitmap.h"

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



        DbgPrint("[*] Prepare for vrtualization...");
        PrepareForVirtualization(VpData, SharedVpData, ContextRecord);

    exit:

    });
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

VOID TerminateVmx()
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

ULONG AdjustControls(ULONG Ctl, ULONG Msr)
{
    MSR MsrValue = { 0 };

    MsrValue.Content = __readmsr(Msr);
    Ctl &= MsrValue.Fields.High; /* bit == 0 in high word ==> must be zero */
    Ctl |= MsrValue.Fields.Low;  /* bit == 1 in low word  ==> must be one  */
    return Ctl;
}

