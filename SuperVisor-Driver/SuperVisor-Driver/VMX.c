#include "VMX.h"
#include "Processor.h"
#include "Assembly.h"

VIRTUAL_MACHINE_STATE* g_GuestState;


BOOLEAN InitializeVmx()
{
    if (!IsVmxSupported())
    {
        DbgPrint("[*] VMX isn't supported in this machine!");
        return FALSE;
    }

    ULONG ProcessorCounts = KeQueryActiveProcessorCount(0);
    g_GuestState = ExAllocatePoolWithTag(NonPagedPool, sizeof(VIRTUAL_MACHINE_STATE) * ProcessorCounts, POOLTAG);

    if (!g_GuestState)
        return FALSE;

    // Initialize vmx on each logical processor (_LogicalProcessorIndex is defined inside the macro)
    RunOnEachLogicalProcessor(
    {
        AsmEnableVmxeBit();
        DbgPrint("[*] VMXe bit Enabled Successfully!");

        AllocateVmxonRegion(g_GuestState + _LogicalProcessorIndex);
        AllocateVmcsRegion(g_GuestState + _LogicalProcessorIndex);

        DbgPrint("[*] VMCS Region is allocated at  ===============> %llx", g_GuestState[_LogicalProcessorIndex].VmcsRegion);
        DbgPrint("[*] VMXON Region is allocated at ===============> %llx", g_GuestState[_LogicalProcessorIndex].VmxonRegion);
    });
}

void TerminateVmx()
{
	DbgPrint("\n[*] Terminating VMX...\n");

    // Terminate vmx on each logical processor (_LogicalProcessorIndex is defined inside the macro)
    RunOnEachLogicalProcessor(
    {
        __vmx_off();
        ExFreePoolWithTag(PhysicalToVirtualAddress(g_GuestState[_LogicalProcessorIndex].VmxonRegion), POOLTAG);
        ExFreePoolWithTag(PhysicalToVirtualAddress(g_GuestState[_LogicalProcessorIndex].VmcsRegion), POOLTAG);
    });

    DbgPrint("[*] VMX Operation turned off successfully!\n");
}
