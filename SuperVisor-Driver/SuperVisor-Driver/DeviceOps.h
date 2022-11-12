#pragma once
#include <ntddk.h>
#include <wdf.h>
#include <wdm.h>
#include "Assembly.h"
#include "SVM.h"

NTSTATUS DriverCreate(PDEVICE_OBJECT DeviceObj, PIRP Irp);
NTSTATUS DriverClose(PDEVICE_OBJECT DeviceObj, PIRP Irp);
NTSTATUS DriverRead(PDEVICE_OBJECT DeviceObj, PIRP Irp);
NTSTATUS DriverWrite(PDEVICE_OBJECT DeviceObj, PIRP Irp);
NTSTATUS DriverIoctl(PDEVICE_OBJECT DeviceObj, PIRP Irp);
NTSTATUS DriverUnsupported(PDEVICE_OBJECT DeviceObj, PIRP Irp);

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