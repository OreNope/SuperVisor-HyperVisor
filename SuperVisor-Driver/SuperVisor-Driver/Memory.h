#pragma once
#include <ntddk.h>

#define POOLTAG 0x53564856 // [S]uper[Visor] - [H]yper[V]isor (SVHV)

UINT64 VirtualToPhysicalAddress(void* Va);
UINT64 PhysicalToVirtualAddress(UINT64 Pa);
