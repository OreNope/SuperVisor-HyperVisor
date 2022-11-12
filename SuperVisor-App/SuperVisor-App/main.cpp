#include <windows.h>
#include <iostream>
#include <string>
#include "main.h"


int main()
{
	std::string CpuID = GetCpuID();

	std::cout << "[*] The CPU Vendor is: " << CpuID << std::endl;

	if (CpuID == "AuthenticAMD")
	{
		std::cout << "[*] The CPU virtualization technology is AMD-V." << std::endl;
	}
	else
	{
		std::cout << "[*] We are currently doesn't support to run in a non-AMD-V environment!" << std::endl;
		return 1;
	}

	if (DetectSvmSupport())
	{
		std::cout << "[*] SVM Operation is supported by your processor." << std::endl;
	}
	else
	{
		std::cout << "[*] SVM Operation is not supported by your processor." << std::endl;
		return 1;
	}

	HANDLE Handle = CreateFile(L"\\\\.\\SuperVisor",
						GENERIC_READ | GENERIC_WRITE,
						FILE_SHARE_READ | FILE_SHARE_WRITE,
						NULL,
						OPEN_EXISTING,
						FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
						NULL
	);

	if (Handle == INVALID_HANDLE_VALUE)
	{
		DWORD ErrNum = GetLastError();
		std::cerr << "[*] CreateFile failed: " << ErrNum << std::endl;
		return 1;
	}

	CHAR InBuff[BUFF_SIZE] = "String by User application! (METHOD_BUFFERED)";
	CHAR OutBuff[BUFF_SIZE] = { '\0' };

	std::cout << "\nCalling DeviceIoControl METHOD_BUFFERED!" << std::endl;

	ULONG BytesReturned;
	BOOL Res = DeviceIoControl(Handle, IOCTL_SIOCTL_METHOD_BUFFERED,
							&InBuff, strlen(InBuff) + 1,
							&OutBuff, sizeof(OutBuff),
							&BytesReturned, NULL
	);

	if (!Res)
	{
		std::cerr << "Error in DeviceIoControl: " << GetLastError() << std::endl;
		return 1;
	}

	std::cout << "OutBuff (" << BytesReturned << "): " << OutBuff << std::endl;

	std::cin.get();

	CloseHandle(Handle);

	return 0;
}

std::string GetCpuID()
{
	char SysType[12];
	std::string CpuID;

	_asm
	{
		// Execute CPUID with EAX = 0 to get the CPU producer
		// Vendor name stored as (EBX + EDX + ECX)
		XOR EAX, EAX
		CPUID
		// Get the first part (EBX)
		MOV DWORD PTR[SysType], EBX
		// Get the second part (EDX)
		MOV DWORD PTR[SysType + 4], EDX
		// Get the third part (ECX)
		MOV DWORD PTR[SysType + 8], ECX
	}

	CpuID.assign(SysType, sizeof(SysType));
	return CpuID;
}

bool DetectSvmSupport()
{
	bool SVM = false;

	__asm {
		mov eax, 0x80000001
		cpuid
		bt ecx, 2 // Check for the 3th bit (index 2)
		jnc SVMNotSupport
		// Supported (set SVM to true)
		mov SVM, 1
		SVMNotSupport:
	}

	return SVM;
}
