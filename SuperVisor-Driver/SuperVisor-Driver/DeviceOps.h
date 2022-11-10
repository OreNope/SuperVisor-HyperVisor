#pragma once
#include <ntddk.h>
#include <wdf.h>
#include <wdm.h>

// Extern from Assembly.asm file
extern void inline AsmEnableVmxeBit(void);

NTSTATUS DriverUnsupported(IN PDEVICE_OBJECT DeviceObj, IN PIRP Irp);
NTSTATUS DriverCreate(IN PDEVICE_OBJECT DeviceObj, IN PIRP Irp);
NTSTATUS DriverClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
NTSTATUS DriverRead(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
NTSTATUS DriverWrite(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
NTSTATUS DriverIoctl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

void PrintIrpInfo(PIRP Irp);

#pragma alloc_text(PAGE, DriverUnsupported)
#pragma alloc_text(PAGE, DriverCreate)
#pragma alloc_text(PAGE, DriverClose)
#pragma alloc_text(PAGE, DriverRead)
#pragma alloc_text(PAGE, DriverWrite)
#pragma alloc_text(PAGE, DriverIoctl)


#define IOCTL_TEST 0x1 // In case of testing
#define SIOCTL_TYPE 40000


#define IOCTL_SIOCTL_METHOD_IN_DIRECT \
    CTL_CODE(SIOCTL_TYPE, 0x900, METHOD_IN_DIRECT, FILE_ANY_ACCESS)

#define IOCTL_SIOCTL_METHOD_OUT_DIRECT \
    CTL_CODE(SIOCTL_TYPE, 0x901, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)

#define IOCTL_SIOCTL_METHOD_BUFFERED \
    CTL_CODE(SIOCTL_TYPE, 0x902, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_SIOCTL_METHOD_NEITHER \
    CTL_CODE(SIOCTL_TYPE, 0x903, METHOD_NEITHER, FILE_ANY_ACCESS)