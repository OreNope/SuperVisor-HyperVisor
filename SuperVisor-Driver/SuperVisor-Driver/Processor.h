#pragma once
#include <ntddk.h>
#include <wdf.h>
#include <wdm.h>

void RunOnEachLogicalProcessor(void (*Callback)(ULONG));
BOOLEAN IsVmxSupported();