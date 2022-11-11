#include "EPT.h"
#include "VMX.h"

extern UINT64 g_VirtualGuestMemoryAddress;

UINT64 InitializeEptp()
{
	PAGED_CODE(); // Assert 

	// Allocate EPTP
	PEPTP EPTPointer = NULL;
	PEPT_PML4E EptPml4 = NULL;
	PEPT_PDPTE EptPdpt = NULL;
	PEPT_PDE EptPD = NULL;
	PEPT_PTE EptPt = NULL;
	
	BYTE* DependencyAllocations[DEPENDENCY_ALLOCATIONS_LEN] = { &EPTPointer, &EptPml4, &EptPdpt, &EptPD, &EptPt };
	
	for (size_t i = 0; i < DEPENDENCY_ALLOCATIONS_LEN; ++i)
	{
		*(DependencyAllocations[i]) = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, POOLTAG);

		if (*(DependencyAllocations[i]) == NULL)
		{
			for (size_t j = 0; j < i; ++j)
			{
				ExFreePoolWithTag(*(DependencyAllocations[j]), POOLTAG);
			}

			return NULL;
		}
		
		RtlZeroMemory(*(DependencyAllocations[i]), PAGE_SIZE);
	}

	const UINT64 PagesToAllocate = 10;
	UINT64 GuestMemory = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE * PagesToAllocate, POOLTAG);


	if (!GuestMemory)
	{
		for (size_t i = 0; i < DEPENDENCY_ALLOCATIONS_LEN; ++i)
		{
			ExFreePoolWithTag(*(DependencyAllocations[i]), POOLTAG);
		}

		return NULL;
	}

	RtlZeroMemory(GuestMemory, PAGE_SIZE * PagesToAllocate);

    g_VirtualGuestMemoryAddress = GuestMemory; // First page

	for (size_t i = 0; i < PagesToAllocate; ++i)
	{
		EptPt[i].Fields.AccessedFlag = 0;
		EptPt[i].Fields.DirtyFlag = 0;
		EptPt[i].Fields.EPTMemoryType = 6;
		EptPt[i].Fields.Execute = 1;
		EptPt[i].Fields.ExecuteForUserMode = 0;
		EptPt[i].Fields.IgnorePAT = 0;
		EptPt[i].Fields.PhysicalAddress = (VirtualToPhysicalAddress(GuestMemory + (i * PAGE_SIZE)) / PAGE_SIZE);
		EptPt[i].Fields.Read = 1;
		EptPt[i].Fields.SuppressVE = 0;
		EptPt[i].Fields.Write = 1;
	}

    //
// Setting up PDE
//
    EptPD->Fields.Accessed = 0;
    EptPD->Fields.Execute = 1;
    EptPD->Fields.ExecuteForUserMode = 0;
    EptPD->Fields.Ignored1 = 0;
    EptPD->Fields.Ignored2 = 0;
    EptPD->Fields.Ignored3 = 0;
    EptPD->Fields.PhysicalAddress = (VirtualToPhysicalAddress(EptPt) / PAGE_SIZE);
    EptPD->Fields.Read = 1;
    EptPD->Fields.Reserved1 = 0;
    EptPD->Fields.Reserved2 = 0;
    EptPD->Fields.Write = 1;

    //
    // Setting up PDPTE
    //
    EptPdpt->Fields.Accessed = 0;
    EptPdpt->Fields.Execute = 1;
    EptPdpt->Fields.ExecuteForUserMode = 0;
    EptPdpt->Fields.Ignored1 = 0;
    EptPdpt->Fields.Ignored2 = 0;
    EptPdpt->Fields.Ignored3 = 0;
    EptPdpt->Fields.PhysicalAddress = (VirtualToPhysicalAddress(EptPD) / PAGE_SIZE);
    EptPdpt->Fields.Read = 1;
    EptPdpt->Fields.Reserved1 = 0;
    EptPdpt->Fields.Reserved2 = 0;
    EptPdpt->Fields.Write = 1;

    //
    // Setting up PML4E
    //
    EptPml4->Fields.Accessed = 0;
    EptPml4->Fields.Execute = 1;
    EptPml4->Fields.ExecuteForUserMode = 0;
    EptPml4->Fields.Ignored1 = 0;
    EptPml4->Fields.Ignored2 = 0;
    EptPml4->Fields.Ignored3 = 0;
    EptPml4->Fields.PhysicalAddress = (VirtualToPhysicalAddress(EptPdpt) / PAGE_SIZE);
    EptPml4->Fields.Read = 1;
    EptPml4->Fields.Reserved1 = 0;
    EptPml4->Fields.Reserved2 = 0;
    EptPml4->Fields.Write = 1;

    //
    // Setting up EPTP
    //
    EPTPointer->Fields.DirtyAndAceessEnabled = 1;
    EPTPointer->Fields.MemoryType = 6; // 6 = Write-back (WB)
    EPTPointer->Fields.PageWalkLength = 3; // 4 (tables walked) - 1 = 3
    EPTPointer->Fields.PML4Address = (VirtualToPhysicalAddress(EptPml4) / PAGE_SIZE);
    EPTPointer->Fields.Reserved1 = 0;
    EPTPointer->Fields.Reserved2 = 0;

    DbgPrint("[*] Extended Page Table Pointer allocated at 0x%p", EPTPointer);

    return EPTPointer;
}
