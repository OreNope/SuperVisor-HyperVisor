#include <windows.h>
#include <iostream>
#include <string>

std::string getCpuID()
{
	char sysType[13];
	std::string cpuID;
						
	_asm
	{
		// Execute CPUID with EAX = 0 to get the CPU producer
		XOR EAX, EAX
		CPUID
		// Get the first part
		MOV DWORD PTR [sysType], EBX
		// Get the second part the same way but these values are stored in EDX
		MOV DWORD PTR [sysType + 4], EDX
		// Get the third part
		MOV DWORD PTR[sysType + 8], ECX
		// Null at the end
		MOV sysType[12], 00
	}

	cpuID.assign(sysType, 12);
	return cpuID;
}

bool detectVmxSupport()
{
	bool VMX = false;

	__asm {
		XOR EAX, EAX
		INC EAX
		CPUID
		BT ECX, 0x5
		JNC VMXNotSupport
		// Supported (set vmx to true)
		MOV VMX, 0x1
		VMXNotSupport:
	}

	return VMX;
}

int main()
{
	std::string cpuID = getCpuID();

	std::cout << "[*] The CPU Vendor is: " << cpuID << std::endl;

	if (cpuID == "GenuineIntel")
	{
		std::cout << "[*] The CPU virtualization technology is VT-x." << std::endl;
	}
	else
	{
		std::cout << "[*] We are currently doesn't support to run in a non-VT-x environment!" << std::endl;
		return 1;
	}

	if (detectVmxSupport())
	{
		std::cout << "[*] VMX Operation is supported by your processor." << std::endl;
	}
	else
	{
		std::cout << "[*] VMX Operation is not supported by your processor." << std::endl;
		return 1;
	}

	HANDLE handle = CreateFile(L"\\\\.\\SuperVisor",
						GENERIC_READ | GENERIC_WRITE,
						FILE_SHARE_READ | FILE_SHARE_WRITE,
						NULL,
						OPEN_EXISTING,
						FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
						NULL
	);

	std::cin.get();

	return 0;
}
