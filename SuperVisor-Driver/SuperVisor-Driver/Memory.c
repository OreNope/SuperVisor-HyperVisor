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