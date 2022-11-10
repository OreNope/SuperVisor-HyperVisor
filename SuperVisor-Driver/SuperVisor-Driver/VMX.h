#pragma once
#include <ntddk.h>
#include <wdf.h>
#include <wdm.h>
#include <intrin.h>
#include "IntelMSR.h"

#define ALIGNMENT_PAGE_SIZE 4096
#define MAXIMUM_ADDRESS     0xffffffffffffffff
#define VMCS_SIZE           4096
#define VMXON_SIZE          4096

typedef struct _VIRTUAL_MACHINE_STATE
{
    UINT64 VmxonRegion; // VMXON region
    UINT64 VmcsRegion;  // VMCS region
} VIRTUAL_MACHINE_STATE, * PVIRTUAL_MACHINE_STATE;

extern VIRTUAL_MACHINE_STATE* g_GuestState;

#define POOLTAG 0x53564856 // [S]uper[Visor] - [H]yper[V]isor (SVHV)

UINT64 VirtualToPhysicalAddress(void* Va);
UINT64 PhysicalToVirtualAddress(UINT64 Pa);
BOOLEAN AllocateVmxonRegion(VIRTUAL_MACHINE_STATE* GuestState);
BOOLEAN AllocateVmcsRegion(VIRTUAL_MACHINE_STATE* GuestState);
BOOLEAN InitializeVmx();
void TerminateVmx();
void TerminateVmxOnLogicalProcessor(ULONG Index);