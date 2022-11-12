#include "SVM.h"
#include "Processor.h"
#include "MsrBitmap.h"
#include <ntifs.h>

BOOLEAN InitializeSvm()
{
    if (!IsSvmSupported())
    {
        DbgPrint("[*] SVM isn't supported in this machine!");
        return FALSE;
    }

    PSHARED_VIRTUAL_PROCESSOR_DATA  sharedVpData = ExAllocatePoolWithTag(NonPagedPool, sizeof(SHARED_VIRTUAL_PROCESSOR_DATA), POOLTAG);

    if (!sharedVpData)
        return FALSE;

    RtlZeroMemory(sharedVpData, sizeof(SHARED_VIRTUAL_PROCESSOR_DATA));

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

}

BOOLEAN VirtualizeProcessor(PSHARED_VIRTUAL_PROCESSOR_DATA SharedVpData)
{
    PCONTEXT ContextRecord = ExAllocatePoolWithTag(NonPagedPool, sizeof(CONTEXT), POOLTAG);

    if (!ContextRecord)
    {
        DbgPrint("Insufficient memory.\n");
        return FALSE;
    }

    PVIRTUAL_PROCESSOR_DATA VpData = ExAllocatePoolWithTag(NonPagedPool, sizeof(VIRTUAL_PROCESSOR_DATA), POOLTAG);


    if (!VpData)
    {
        DbgPrint("Insufficient memory.\n");
        ExFreePoolWithTag(ContextRecord, POOLTAG);
        return FALSE;
    }

    RtlZeroMemory(VpData, sizeof(VIRTUAL_PROCESSOR_DATA));

    // captured state is used as an initial state of the guest mode
    RtlCaptureContext(ContextRecord);

    // Enable SVM by setting EFER.SVME
    __writemsr(IA32_MSR_EFER, __readmsr(IA32_MSR_EFER) | EFER_SVME);
    DbgPrint("[*] SVM Enabled Successfully!");

    DbgPrint("[*] Setup VMCBs!");
    SetupVMCBs(VpData, SharedVpData, ContextRecord);

    DbgPrint("[*] Called to LaunchVM!");
    AsmLaunchVm(&VpData->HostStackLayout.GuestVmcbPa);

    // If the code runs LaunchVM failed so we set an break point to not cause bsod
    __debugbreak(); // int 3h

    return TRUE;
}

BOOLEAN HandleVmExit(_Inout_ PVIRTUAL_PROCESSOR_DATA VpData, _Inout_ PGUEST_REGISTERS GuestRegisters)
{
    GUEST_CONTEXT guestContext;
    KIRQL oldIrql;

    guestContext.VpRegs = GuestRegisters;
    guestContext.ExitVm = FALSE;

    // Load some host state that are not loaded on #VMEXIT.
    __svm_vmload(VpData->HostStackLayout.HostVmcbPa);

    NT_ASSERT(VpData->HostStackLayout.Reserved1 == MAXUINT64);

    // Raise the IRQL to the DISPATCH_LEVEL level. This has no actual effect since
    // interrupts are disabled at #VMEXI but warrants bug check when some of
    // kernel API that are not usable.
    oldIrql = KeGetCurrentIrql();
    if (oldIrql < DISPATCH_LEVEL)
    {
        KeRaiseIrqlToDpcLevel();
    }

    // Guest's RAX is overwritten by the host's value on #VMEXIT and saved in
    // the VMCB instead. Reflect the guest RAX to the context.
    GuestRegisters->Rax = VpData->GuestVmcb.StateSaveArea.Rax;

    // Update the _KTRAP_FRAME structure values in hypervisor stack, so that
    // Windbg can reconstruct call stack of the guest during debug session.
    // This is optional but very useful thing to do for debugging.
    VpData->HostStackLayout.TrapFrame.Rsp = VpData->GuestVmcb.StateSaveArea.Rsp;
    VpData->HostStackLayout.TrapFrame.Rip = VpData->GuestVmcb.ControlArea.NRip;

    // Handle #VMEXIT according with its reason.
    switch (VpData->GuestVmcb.ControlArea.ExitCode)
    {
        case VMEXIT_CPUID:
            HandleCpuid(VpData, &guestContext);
            break;
        case VMEXIT_MSR:
            HandleMsrAccess(VpData, &guestContext);
            break;
        case VMEXIT_VMRUN:
            SvInjectGeneralProtectionException(VpData);
            break;
        default:
            __debugbreak(); // int 3h to not cause bsod
    }

    // Again, no effect to change IRQL but restoring it here since a #VMEXIT
    // handler where the developers most likely call the kernel API inadvertently
    // is already executed.
    if (oldIrql < DISPATCH_LEVEL)
    {
        KeLowerIrql(oldIrql);
    }

    // Terminate the hypervisor if requested.
    if (guestContext.ExitVm != FALSE)
    {
        NT_ASSERT(VpData->GuestVmcb.ControlArea.ExitCode == VMEXIT_CPUID);

        // Set return values of CPUID instruction as follows:
        //  RBX     = An address to return
        //  RCX     = A stack pointer to restore
        //  EDX:EAX = An address of per processor data to be freed by the caller
        guestContext.VpRegs->Rax = ((UINT64)VpData) & MAXUINT32;
        guestContext.VpRegs->Rbx = VpData->GuestVmcb.ControlArea.NRip;
        guestContext.VpRegs->Rcx = VpData->GuestVmcb.StateSaveArea.Rsp;
        guestContext.VpRegs->Rdx = ((UINT64)VpData) >> 32;

        // Load guest state (currently host state is loaded).
        __svm_vmload(MmGetPhysicalAddress(&VpData->GuestVmcb).QuadPart);

        // Set the global interrupt flag (GIF) but still disable interrupts by
        // clearing IF. GIF must be set to return to the normal execution, but
        // interruptions are not desirable until SVM is disabled as it would
        // execute random kernel-code in the host context.
        _disable();
        __svm_stgi();

        // Disable SVM, and restore the guest RFLAGS. This may enable interrupts.
        // Some of arithmetic flags are destroyed by the subsequent code.
        
        __writemsr(IA32_MSR_EFER, __readmsr(IA32_MSR_EFER) & ~EFER_SVME);
        __writeeflags(VpData->GuestVmcb.StateSaveArea.Rflags);
        goto Exit;
    }

    // Reflect potentially updated guest's RAX to VMCB. Again, unlike other GPRs,
    // RAX is loaded from VMCB on VMRUN.
    
    VpData->GuestVmcb.StateSaveArea.Rax = guestContext.VpRegs->Rax;

Exit:
    NT_ASSERT(VpData->HostStackLayout.Reserved1 == MAXUINT64);
    return guestContext.ExitVm;
}

VOID HandleCpuid(_Inout_ PVIRTUAL_PROCESSOR_DATA VpData, _Inout_ PGUEST_CONTEXT GuestContext)
{
    CPUID registers;   // EAX, EBX, ECX, and EDX
    int leaf, subLeaf;
    SEGMENT_ATTRIBUTE attribute;

    // Execute CPUID as requested.
    leaf = (int)(GuestContext->VpRegs->Rax);
    subLeaf = (int)(GuestContext->VpRegs->Rcx);
    __cpuidex((int*)&registers, leaf, subLeaf);

    switch (leaf)
    {
        case CPUID_PROCESSOR_AND_PROCESSOR_FEATURE_IDENTIFIERS:
            //
            // Indicate presence of a hypervisor by setting the bit that are
            // reserved for use by hypervisor to indicate guest status. See "CPUID
            // Fn0000_0001_ECX Feature Identifiers".
            //
            registers.ecx |= CPUID_FN0000_0001_ECX_HYPERVISOR_PRESENT;
            break;
        case CPUID_HV_VENDOR_AND_MAX_FUNCTIONS:
            //
            // Return a maximum supported hypervisor CPUID leaf range and a vendor
            // ID signature as required by the spec.
            //
            registers.eax = CPUID_HV_MAX;
            registers.ebx = 'epuS';  // "SuperVisor  "
            registers.ecx = 'siVr';
            registers.edx = '  ro';
            break;
        case CPUID_HV_INTERFACE:

            // Return non Hv#1 value. This indicate that the hypervisor does NOT
            // conform to the Microsoft hypervisor interface.

            registers.eax = '0#vH';  // Hv#0
            registers.ebx = registers.ecx = registers.edx = 0;
            break;
        case CPUID_UNLOAD_SUPERVISOR:
            if (subLeaf == CPUID_UNLOAD_SUPERVISOR)
            {
                // Unload itself if the request is from the kernel mode.
                attribute.AsUInt16 = VpData->GuestVmcb.StateSaveArea.SsAttrib;
                if (attribute.Fields.Dpl == DPL_SYSTEM)
                {
                    GuestContext->ExitVm = TRUE;
                }
            }
            break;
        default:
            break;
    }

    // Update guest's GPRs with results.
    GuestContext->VpRegs->Rax = registers.eax;
    GuestContext->VpRegs->Rbx = registers.ebx;
    GuestContext->VpRegs->Rcx = registers.ecx;
    GuestContext->VpRegs->Rdx = registers.edx;

    // Debug prints results. Very important to note that any use of API from
    // the host context is unsafe and absolutely avoided, unless the API is
    // documented to be accessible on IRQL IPI_LEVEL+. This is because
    // interrupts are disabled when host code is running, and IPI is not going
    // to be delivered when it is issued.
    
    // This code is not exception and violating this rule. The reasons for this
    // code are to demonstrate a bad example, and simply show that the HyperVisor
    // is functioning for a test purpose.

    if (KeGetCurrentIrql() <= DISPATCH_LEVEL)
        DbgPrint("CPUID: %08x-%08x : %08x %08x %08x %08x\n",leaf, subLeaf, registers.eax, registers.ebx, registers.ecx, registers.edx);

    // Then, advance RIP to "complete" the instruction.
    VpData->GuestVmcb.StateSaveArea.Rip = VpData->GuestVmcb.ControlArea.NRip;
}

VOID HandleMsrAccess(_Inout_ PVIRTUAL_PROCESSOR_DATA VpData, _Inout_ PGUEST_CONTEXT GuestContext)
{
    ULARGE_INTEGER value;
    UINT32 msr;
    BOOLEAN writeAccess;

    msr = GuestContext->VpRegs->Rcx & MAXUINT32;
    writeAccess = (VpData->GuestVmcb.ControlArea.ExitInfo1 != 0);

    // If IA32_MSR_EFER is accessed for write, we must protect the EFER_SVME bit
    // from being cleared.
    if (msr == IA32_MSR_EFER)
    {
        // #VMEXIT on IA32_MSR_EFER access should only occur on write access.
        NT_ASSERT(writeAccess != FALSE);

        value.LowPart = GuestContext->VpRegs->Rax & MAXUINT32;
        value.HighPart = GuestContext->VpRegs->Rdx & MAXUINT32;

        if ((value.QuadPart & EFER_SVME) == 0)
        {
            // Inject #GP if the guest attempts to clear the SVME bit. Protection of
            // this bit is required because clearing the bit while guest is running
            // leads to undefined behavior.

            SvInjectGeneralProtectionException(VpData);
        }

        // Otherwise, update the MSR as requested. Important to note that the value
        // should be checked not to allow any illegal values, and inject #GP as
        // needed. Otherwise, the hypervisor attempts to resume the guest with an
        // illegal EFER and immediately receives #VMEXIT due to VMEXIT_INVALID,
        // which in our case, results in a bug check. See "Extended Feature Enable
        // Register (EFER)" for what values are allowed.
        
        // This code does not implement the check intentionally, for simplicity.
        
        VpData->GuestVmcb.StateSaveArea.Efer = value.QuadPart;
    }
    else
    {
        // If the MSR being accessed is not IA32_MSR_EFER, assert that #VMEXIT
        // can only occur on access to MSR outside the ranges controlled with
        // the MSR permissions map. This is true because the map is configured
        // not to intercept any MSR access but IA32_MSR_EFER. See
        // "MSR Ranges Covered by MSRPM" in "MSR Intercepts" for the MSR ranges
        // controlled by the map.
        
        // Note that VMware Workstation has a bug that access to unimplemented
        // MSRs unconditionally causes #VMEXIT ignoring bits in the MSR
        // permissions map. This can be tested by reading MSR zero, for example.
        NT_ASSERT(((msr > 0x00001fff) && (msr < 0xc0000000)) ||
            ((msr > 0xc0001fff) && (msr < 0xc0010000)) ||
            (msr > 0xc0011fff));

        // Execute WRMSR or RDMSR on behalf of the guest. Important that this
        // can cause bug check when the guest tries to access unimplemented MSR
        // *even within the SEH block* because the below WRMSR or RDMSR raises
        // #GP and are not protected by the SEH block (or cannot be protected
        // either as this code run outside the thread stack region Windows
        // requires to proceed SEH). Hypervisors typically handle this by noop-ing
        // WRMSR and returning zero for RDMSR with non-architecturally defined
        // MSRs. Alternatively, one can probe which MSRs should cause #GP prior
        // to installation of a hypervisor and the hypervisor can emulate the
        // results.
        if (writeAccess != FALSE)
        {
            value.LowPart = GuestContext->VpRegs->Rax & MAXUINT32;
            value.HighPart = GuestContext->VpRegs->Rdx & MAXUINT32;
            __writemsr(msr, value.QuadPart);
        }
        else
        {
            value.QuadPart = __readmsr(msr);
            GuestContext->VpRegs->Rax = value.LowPart;
            GuestContext->VpRegs->Rdx = value.HighPart;
        }
    }

    // Then, advance RIP to "complete" the instruction.
    VpData->GuestVmcb.StateSaveArea.Rip = VpData->GuestVmcb.ControlArea.NRip;
}

VOID SvInjectGeneralProtectionException(_Inout_ PVIRTUAL_PROCESSOR_DATA VpData)
{
    EVENTINJ event;

    // Inject #GP(vector = 13, type = 3 = exception) with a valid error code.
    // An error code are always zero. See "#GP-General-Protection Exception
    // (Vector 13)" for details about the error code.
    
    event.AsUInt64 = 0;
    event.Fields.Vector = 13;
    event.Fields.Type = 3;
    event.Fields.ErrorCodeValid = 1;
    event.Fields.Valid = 1;
    VpData->GuestVmcb.ControlArea.EventInj = event.AsUInt64;
}
