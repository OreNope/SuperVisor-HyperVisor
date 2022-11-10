#include "DeviceOps.h"

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObj, PUNICODE_STRING RegistryPath);
void DriverUnload(PDRIVER_OBJECT DriverObj);

#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, DriverUnload)

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObj, PUNICODE_STRING RegistryPath)
{
	NTSTATUS NtStatus = STATUS_SUCCESS;
	PDRIVER_OBJECT DeviceObject = NULL;
	UNICODE_STRING DriverName, DosDeviceName;

	DbgPrint("DriverEntry Called!");

	RtlInitUnicodeString(&DriverName, L"\\Device\\SuperVisor");
	RtlInitUnicodeString(&DosDeviceName, L"\\DosDevice\\SuperVisor");

	NtStatus = IoCreateDevice(DriverObj, 0, &DriverName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &DeviceObject);

	if (NtStatus == STATUS_SUCCESS)
	{
		DbgPrint("[*] Setting Device's major functions!");

		for (UINT64 Index = 0; Index < IRP_MJ_MAXIMUM_FUNCTION; ++Index)
		{
			DriverObj->MajorFunction[Index] = DriverUnsupported;
		}

		DriverObj->MajorFunction[IRP_MJ_CREATE] = DriverCreate;
		DriverObj->MajorFunction[IRP_MJ_CLOSE] = DriverClose;
		DriverObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverIoctl;


		DriverObj->MajorFunction[IRP_MJ_READ] = DriverRead;
		DriverObj->MajorFunction[IRP_MJ_WRITE] = DriverWrite;

		DriverObj->DriverUnload = DriverUnload;
		IoCreateSymbolicLink(&DosDeviceName, &DriverName);
	}

	return NtStatus;
}

void DriverUnload(PDRIVER_OBJECT DriverObj)
{
	UNICODE_STRING DosDeviceName;

	DbgPrint("DriverUnload Called!");

	RtlInitUnicodeString(&DosDeviceName, L"\\DosDevice\\SuperVisor");

	IoDeleteSymbolicLink(&DosDeviceName);
	IoDeleteDevice(DriverObj->DeviceObject);
}
