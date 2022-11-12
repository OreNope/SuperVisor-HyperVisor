#include "Memory.h"

UINT64 VirtualToPhysicalAddress(void* Va)
{
    return MmGetPhysicalAddress(Va).QuadPart;
}

UINT64 PhysicalToVirtualAddress(UINT64 Pa)
{
    PHYSICAL_ADDRESS PhysicalAddr;
    PhysicalAddr.QuadPart = Pa;

    return (UINT64)MmGetVirtualForPhysical(PhysicalAddr);
}
