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

    // Initialize vmx on each logical processor
    RunOnEachLogicalProcessor(InitializeVmxOnLogicalProcessor);
}

void InitializeVmxOnLogicalProcessor(ULONG Index)
{
    AsmEnableVmxeBit();
    DbgPrint("[*] VMXe bit Enabled Successfully!");

    AllocateVmxonRegion(g_GuestState + Index);
    AllocateVmcsRegion(g_GuestState + Index);

    DbgPrint("[*] VMCS Region is allocated at  ===============> %llx", g_GuestState[Index].VmcsRegion);
    DbgPrint("[*] VMXON Region is allocated at ===============> %llx", g_GuestState[Index].VmxonRegion);
}

void TerminateVmx()
{
	DbgPrint("\n[*] Terminating VMX...\n");

    // Terminate vmx on each logical processor
    RunOnEachLogicalProcessor(TerminateVmxOnLogicalProcessor);

    DbgPrint("[*] VMX Operation turned off successfully!\n");
}

void TerminateVmxOnLogicalProcessor(ULONG Index)
{
    __vmx_off();
    MmFreeContiguousMemory(PhysicalToVirtualAddress(g_GuestState[Index].VmxonRegion));
    MmFreeContiguousMemory(PhysicalToVirtualAddress(g_GuestState[Index].VmcsRegion));
}
