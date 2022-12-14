#pragma once
#include <ntddk.h>
#include <wdf.h>
#include "SLAT.h"


#define RunOnEachLogicalProcessor(Operations) for (ULONG _LogicalProcessorIndex = 0; _LogicalProcessorIndex < KeQueryActiveProcessorCount(NULL); ++_LogicalProcessorIndex)\
												{\
													KeSetSystemAffinityThread(1LL << _LogicalProcessorIndex);\
													DbgPrint("============= Executing in %uth logical processor =============", _LogicalProcessorIndex + 1);\
													Operations\
												}

BOOLEAN IsSvmSupported();
