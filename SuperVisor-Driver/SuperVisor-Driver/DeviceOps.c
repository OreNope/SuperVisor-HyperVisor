#include "DeviceOps.h"


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
	AsmEnableVmxeBit();

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

NTSTATUS DriverIoctl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	PIO_STACK_LOCATION IrpStack;
	NTSTATUS NtStatus = STATUS_SUCCESS;
	ULONG InBufLen;
	ULONG OutBufLen;
	PCHAR InBuf, OutBuf;
	PCHAR Data = "Device driver string!";
	size_t DataLen = strlen(Data) + 1;

	PAGED_CODE(); // Assert

	IrpStack = IoGetCurrentIrpStackLocation(Irp);
	InBufLen = IrpStack->Parameters.DeviceIoControl.InputBufferLength;
	OutBufLen = IrpStack->Parameters.DeviceIoControl.OutputBufferLength;

	if (!InBufLen || OutBufLen < DataLen)
	{
		NtStatus = STATUS_INVALID_PARAMETER;
		goto End;
	}

	switch (IrpStack->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_SIOCTL_METHOD_BUFFERED:
		break;

	case IOCTL_SIOCTL_METHOD_NEITHER:
		break;

	case IOCTL_SIOCTL_METHOD_IN_DIRECT:
		break;

	case IOCTL_SIOCTL_METHOD_OUT_DIRECT:
		break;

	default:
		// The specified I/O control code is unrecognized by this driver.
		NtStatus = STATUS_INVALID_DEVICE_REQUEST;
		DbgPrint("ERROR: unrecognized IOCTL %x\n", IrpStack->Parameters.DeviceIoControl.IoControlCode);
		break;
	}

	DbgPrint("[*] Not implemented yet :( !");

End:

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return NtStatus;
}

void PrintIrpInfo(PIRP Irp)
{
	PIO_STACK_LOCATION IrpStack = IoGetCurrentIrpStackLocation(Irp);

	PAGED_CODE(); // Assert for irq level

	DbgPrint("Irp->AssociatedIrp.SystemBuffer = 0x%p\n", Irp->AssociatedIrp.SystemBuffer);
	DbgPrint("Irp->UserBuffer = 0x%p\n", Irp->UserBuffer);
	DbgPrint("IrpStack->Parameters.DeviceIoControl.Type3InputBuffer = 0x%p\n", IrpStack->Parameters.DeviceIoControl.Type3InputBuffer);
	DbgPrint("IrpStack->Parameters.DeviceIoControl.InputBufferLength = %u\n", IrpStack->Parameters.DeviceIoControl.InputBufferLength);
	DbgPrint("IrpStack->Parameters.DeviceIoControl.OutputBufferLength = %u\n", IrpStack->Parameters.DeviceIoControl.OutputBufferLength);
}
