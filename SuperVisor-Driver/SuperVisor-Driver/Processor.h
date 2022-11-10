#pragma once
#include <ntddk.h>
#include <wdf.h>
#include <wdm.h>


#define RunOnEachLogicalProcessor(Operations) for (size_t _LogicalProcessorIndex = 0; _LogicalProcessorIndex < KeQueryActiveProcessorCount(NULL); ++_LogicalProcessorIndex)\
												{\
													KeSetSystemAffinityThread(1LL << _LogicalProcessorIndex);\
													DbgPrint("============= Executing in %dth logical processor =============", (int)(_LogicalProcessorIndex + 1));\
													Operations\
												}

BOOLEAN IsVmxSupported();