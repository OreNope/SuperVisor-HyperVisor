#pragma once
#include <ntddk.h>
#include <wdm.h>
#include <wdf.h>

#define DEPENDENCY_ALLOCATIONS_LEN 5

#ifndef POOLTAG
#define POOLTAG 0x53564856 // [S]uper[Visor] - [H]yper[V]isor (SVHV)
#endif

typedef struct _PML4_ENTRY
{
    union
    {
        UINT64 AsUInt64;
        struct
        {
            UINT64 Valid : 1;               // [0]
            UINT64 Write : 1;               // [1]
            UINT64 User : 1;                // [2]
            UINT64 WriteThrough : 1;        // [3]
            UINT64 CacheDisable : 1;        // [4]
            UINT64 Accessed : 1;            // [5]
            UINT64 Reserved1 : 3;           // [6:8]
            UINT64 Avl : 3;                 // [9:11]
            UINT64 PageFrameNumber : 40;    // [12:51]
            UINT64 Reserved2 : 11;          // [52:62]
            UINT64 NoExecute : 1;           // [63]
        } Fields;
    };
} PML4_ENTRY, *PPML4_ENTRY,
PDP_ENTRY, *PPDP_ENTRY;

typedef struct _PD_ENTRY
{
    union
    {
        UINT64 AsUInt64;
        struct
        {
            UINT64 Valid : 1;               // [0]
            UINT64 Write : 1;               // [1]
            UINT64 User : 1;                // [2]
            UINT64 WriteThrough : 1;        // [3]
            UINT64 CacheDisable : 1;        // [4]
            UINT64 Accessed : 1;            // [5]
            UINT64 Dirty : 1;               // [6]
            UINT64 LargePage : 1;           // [7]
            UINT64 Global : 1;              // [8]
            UINT64 Avl : 3;                 // [9:11]
            UINT64 Pat : 1;                 // [12]
            UINT64 Reserved1 : 8;           // [13:20]
            UINT64 PageFrameNumber : 31;    // [21:51]
            UINT64 Reserved2 : 11;          // [52:62]
            UINT64 NoExecute : 1;           // [63]
        } Fields;
    };
} PD_ENTRY, *PPD_ENTRY;

typedef struct _SHARED_VIRTUAL_PROCESSOR_DATA
{
    PVOID MsrPermissionsMap;
    DECLSPEC_ALIGN(PAGE_SIZE) PML4_ENTRY Pml4Entries[1];    // Just for 512 GB
    DECLSPEC_ALIGN(PAGE_SIZE) PDP_ENTRY PdpEntries[512];
    DECLSPEC_ALIGN(PAGE_SIZE) PD_ENTRY PdeEntries[512][512];
} SHARED_VIRTUAL_PROCESSOR_DATA, *PSHARED_VIRTUAL_PROCESSOR_DATA;

BOOLEAN InitializeSLAT(_Out_ PSHARED_VIRTUAL_PROCESSOR_DATA SharedVpData);
