#pragma once
#include <ntddk.h>
#include <wdf.h>
#include <wdm.h>

extern void inline AsmEnableVmxOperation(void);

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObj, PUNICODE_STRING RegistryPath);
void DriverUnload(PDRIVER_OBJECT DriverObj);

#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, DriverUnload)

NTSTATUS DriverUnsupported(IN PDEVICE_OBJECT DeviceObj, IN PIRP Irp);
NTSTATUS DriverCreate(IN PDEVICE_OBJECT DeviceObj, IN PIRP Irp);
NTSTATUS DriverClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
NTSTATUS DriverIoctlDispatcher(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
NTSTATUS DriverRead(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
NTSTATUS DriverWrite(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
