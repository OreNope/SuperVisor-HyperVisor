#include "main.h"


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
		DriverObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverIoctlDispatcher;


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

NTSTATUS DriverUnsupported(IN PDEVICE_OBJECT DeviceObj, IN PIRP Irp)
{
	DbgPrint("[*] This function is not supported :( !");

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS DriverCreate(IN PDEVICE_OBJECT DeviceObj, IN PIRP Irp)
{
	AsmEnableVmx();

	DbgPrint("[*] VMX Operation Enabled!");

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS DriverClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	DbgPrint("[*] Not implemented yet :( !");

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS DriverIoctlDispatcher(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	DbgPrint("[*] Not implemented yet :( !");

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS DriverRead(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	DbgPrint("[*] Not implemented yet :( !");

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS DriverWrite(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	DbgPrint("[*] Not implemented yet :( !");

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}
