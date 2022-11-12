#pragma once
#include <ntddk.h>
#include "AMDMSR.h"

#define SVM_MSR_PERMISSIONS_MAP_SIZE    (PAGE_SIZE * 2)

BOOLEAN InitializeMsrBitmap(_Out_ PVOID MsrBitmap);