#include "MsrBitmap.h"
#include <intrin.h>

BOOLEAN InitializeMsrBitmap(_Out_ PVOID MsrBitmap)
{
    static const UINT32 BITS_PER_MSR = 2;
    static const UINT32 SECOND_MSR_RANGE_BASE = 0xc0000000;
    static const UINT32 SECOND_MSRPM_OFFSET = 0x800 * CHAR_BIT;
    RTL_BITMAP bitmapHeader;
    ULONG offsetFrom2ndBase, offset;

    if (!MsrBitmap)
        return FALSE;

    // Setup and clear all bits, indicating no MSR access should be intercepted.
    RtlInitializeBitMap(&bitmapHeader, (PULONG)MsrBitmap, SVM_MSR_PERMISSIONS_MAP_SIZE * CHAR_BIT);
    RtlClearAllBits(&bitmapHeader);

    // Compute an offset from the second MSR bitmap offset (0x800) for
    // IA32_MSR_EFER in bits. Then, add an offset until the second MSR
    // bitmap.
    offsetFrom2ndBase = (IA32_MSR_EFER - SECOND_MSR_RANGE_BASE) * BITS_PER_MSR;
    offset = SECOND_MSRPM_OFFSET + offsetFrom2ndBase;

    // Set the MSB bit indicating write accesses to the MSR should be intercepted.
    RtlSetBits(&bitmapHeader, offset + 1, 1);

    return TRUE;
}