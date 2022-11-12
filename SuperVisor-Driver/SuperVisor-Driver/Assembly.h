#pragma once
#include <ntddk.h>
#include "SegmentsAndDescriptors.h"

// Extern from Assembly.asm file
extern VOID AsmLaunchVm(_In_ PVOID HostRsp);
extern AsmGetGdt(_Out_ DESCRIPTOR_TABLE_REGISTER* gdt);

