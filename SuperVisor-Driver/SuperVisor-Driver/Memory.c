#include "VMX.h"


UINT64 VirtualToPhysicalAddress(void* Va)
{
    return MmGetPhysicalAddress(Va).QuadPart;
}

UINT64 PhysicalToVirtualAddress(UINT64 Pa)
{
    PHYSICAL_ADDRESS PhysicalAddr;
    PhysicalAddr.QuadPart = Pa;

    return MmGetVirtualForPhysical(PhysicalAddr);
}

BOOLEAN AllocateVmxonRegion(VIRTUAL_MACHINE_STATE* GuestState)
{
    if (KeGetCurrentIrql() > DISPATCH_LEVEL)
        KeRaiseIrqlToDpcLevel();

    PHYSICAL_ADDRESS PhysicalMax = { 0 };
    PhysicalMax.QuadPart = MAXULONG64;

    BYTE* VirtualBuff = ExAllocatePoolWithTag(NonPagedPool, VMXON_SIZE, POOLTAG);

    if (VirtualBuff == NULL)
    {
        DbgPrint("[*] Error : Couldn't Allocate Buffer for VMXON Region.");
        return FALSE; // NtStatus = STATUS_INSUFFICIENT_RESOURCES
    }

    UINT64 PhysicalBuff = VirtualToPhysicalAddress(VirtualBuff);
    RtlSecureZeroMemory(VirtualBuff, VMXON_SIZE);

    DbgPrint("[*] Virtual allocated buffer for VMXON at 0x%p", VirtualBuff);
    DbgPrint("[*] Physical allocated buffer for VMXON at %llx", PhysicalBuff);

    // get IA32_VMX_BASIC_MSR RevisionId
    IA32_VMX_BASIC_MSR basic = { 0 };
    basic.All = __readmsr(MSR_IA32_VMX_BASIC);
    DbgPrint("[*] MSR_IA32_VMX_BASIC (MSR 0x480) Revision Identifier %x", basic.Fields.RevisionIdentifier);

    *(UINT64*)VirtualBuff = basic.Fields.RevisionIdentifier;

    int Status = __vmx_on(&PhysicalBuff);
    if (Status)
    {
        DbgPrint("[*] VMXON failed with status %u\n", Status);
        return FALSE;
    }

    GuestState->VmxonRegion = PhysicalBuff;

    return TRUE;
}

BOOLEAN AllocateVmcsRegion(VIRTUAL_MACHINE_STATE* GuestState)
{
    if (KeGetCurrentIrql() > DISPATCH_LEVEL)
        KeRaiseIrqlToDpcLevel();

    PHYSICAL_ADDRESS PhysicalMax = { 0 };
    PhysicalMax.QuadPart = MAXULONG64;

    BYTE* VirtualBuff = ExAllocatePoolWithTag(NonPagedPool, VMCS_SIZE, POOLTAG);

    if (VirtualBuff == NULL)
    {
        DbgPrint("[*] Error : Couldn't Allocate Buffer for VMXCS Region.");
        return FALSE; // NtStatus = STATUS_INSUFFICIENT_RESOURCES
    }

    UINT64 PhysicalBuff = VirtualToPhysicalAddress(VirtualBuff);
    RtlSecureZeroMemory(VirtualBuff, VMXON_SIZE);

    DbgPrint("[*] Virtual allocated buffer for VMCS at 0x%p", VirtualBuff);
    DbgPrint("[*] Physical allocated buffer for VMCS at %llx", PhysicalBuff);

    // get IA32_VMX_BASIC_MSR RevisionId
    IA32_VMX_BASIC_MSR basic = { 0 };
    basic.All = __readmsr(MSR_IA32_VMX_BASIC);
    DbgPrint("[*] MSR_IA32_VMX_BASIC (MSR 0x480) Revision Identifier %x", basic.Fields.RevisionIdentifier);

    *(UINT64*)VirtualBuff = basic.Fields.RevisionIdentifier;

    GuestState->VmcsRegion = PhysicalBuff;

    return TRUE;
}

BOOLEAN AllocateVmmStack(ULONG ProcessorID)
{
    // Allocate stack for the VM Exit Handler
    UINT64 VmmStackVa = ExAllocatePoolWithTag(NonPagedPool, VMM_STACK_SIZE, POOLTAG);
    g_GuestState[ProcessorID].VmmStack = VmmStackVa;

    if (g_GuestState[ProcessorID].VmmStack == NULL)
    {
        DbgPrint("[*] Error in allocating VMM Stack\n");
        return FALSE;
    }
    RtlZeroMemory(g_GuestState[ProcessorID].VmmStack, VMM_STACK_SIZE);

    DbgPrint("[*] VMM Stack for logical processor %d : %llx\n", ProcessorID, g_GuestState[ProcessorID].VmmStack);

    return TRUE;
}

BOOLEAN AllocateMsrBitmap(ULONG ProcessorID)
{
    // Allocate memory for MsrBitmap
    g_GuestState[ProcessorID].MsrBitmap = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, POOLTAG); // should be aligned

    if (g_GuestState[ProcessorID].MsrBitmap == NULL)
    {
        DbgPrint("[*] Error in allocating MSRBitMap.\n");
        return FALSE;
    }
    RtlZeroMemory(g_GuestState[ProcessorID].MsrBitmap, PAGE_SIZE);

    g_GuestState[ProcessorID].MsrBitmapPhysical = VirtualToPhysicalAddress(g_GuestState[ProcessorID].MsrBitmap);

    DbgPrint("[*] MSR Bitmap address : %llx\n", g_GuestState[ProcessorID].MsrBitmap);

    return TRUE;
}