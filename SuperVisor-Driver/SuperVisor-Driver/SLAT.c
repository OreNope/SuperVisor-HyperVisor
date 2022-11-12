#include "SLAT.h"
#include "SVM.h"

BOOLEAN InitializeSLAT(_Out_ PSHARED_VIRTUAL_PROCESSOR_DATA SharedVpData)
{
    ULONG64 pdpBasePa, pdeBasePa, translationPa;

	PAGED_CODE(); // Assert 

    //
    // Build only one PML4 entry. This entry has subtables that control up to
    // 512GB physical memory. PFN points to a base physical address of the page
    // directory pointer table.
    //
    if (!SharedVpData)
    {
        DbgPrint("Shared virtual processor passed to InitializeSLAT is invalid!");
        return FALSE;
    }

    pdpBasePa = VirtualToPhysicalAddress(&SharedVpData->PdpEntries);
    SharedVpData->Pml4Entries[0].Fields.PageFrameNumber = pdpBasePa >> PAGE_SHIFT;

    // The US (User) bit of all nested page table entries to be translated
    // without #VMEXIT, as all guest accesses are treated as user
    SharedVpData->Pml4Entries[0].Fields.Valid = 1;
    SharedVpData->Pml4Entries[0].Fields.Write = 1;
    SharedVpData->Pml4Entries[0].Fields.User = 1;

    // One PML4 entry controls 512 page directory pointer entires.
    for (ULONG64 i = 0; i < 512; ++i)
    {
        // PFN points to a base physical address of the page directory table.
        pdeBasePa = VirtualToPhysicalAddress(&SharedVpData->PdeEntries[i][0]);
        SharedVpData->PdpEntries[i].Fields.PageFrameNumber = pdeBasePa >> PAGE_SHIFT;
        SharedVpData->PdpEntries[i].Fields.Valid = 1;
        SharedVpData->PdpEntries[i].Fields.Write = 1;
        SharedVpData->PdpEntries[i].Fields.User = 1;

        // One page directory entry controls 512 page directory entries.

        for (ULONG64 j = 0; j < 512; ++j)
        {
            translationPa = (i * 512) + j;
            SharedVpData->PdeEntries[i][j].Fields.PageFrameNumber = translationPa;
            SharedVpData->PdeEntries[i][j].Fields.Valid = 1;
            SharedVpData->PdeEntries[i][j].Fields.Write = 1;
            SharedVpData->PdeEntries[i][j].Fields.User = 1;
            SharedVpData->PdeEntries[i][j].Fields.LargePage = 1;
        }
    }

    DbgPrint("[*] Nested Page Table allocated!");

    return TRUE;
}
