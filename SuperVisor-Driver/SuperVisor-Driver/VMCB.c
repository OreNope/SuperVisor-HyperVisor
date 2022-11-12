#include "VMCB.h"
#include <intrin.h>


VOID SetupVMCBs(_Inout_ PVIRTUAL_PROCESSOR_DATA VpData, _In_ PSHARED_VIRTUAL_PROCESSOR_DATA SharedVpData, _In_ const PCONTEXT ContextRecord)
{
    DESCRIPTOR_TABLE_REGISTER gdtr, idtr;
    UINT64 guestVmcbPa, hostVmcbPa, hostStateAreaPa, pml4BasePa, msrpmPa;

    // Capture the current GDTR and IDTR to use as initial values of the guest mode.
    AsmGetGdt(&gdtr);
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
