#include "Processor.h"
#include <intrin.h>
#include "IntelMSR.h"

void RunOnEachLogicalProcessor(void (*Callback)(ULONG))
{
	KAFFINITY AffinityMask;
	ULONG ActiveProcessors = KeQueryActiveProcessorCount(NULL);

	for (ULONG i = 0; i < ActiveProcessors; ++i)
	{
		AffinityMask = 1LL << i;
		KeSetSystemAffinityThread(AffinityMask);

		DbgPrint("============= Executing in %dth logical processor =============", i + 1);

		Callback(i);
	}
}

BOOLEAN IsVmxSupported()
{
	CPUID Data = { 0 };

	// Check for the VMX bit

	__cpuid((int*)&Data, 1);

	if (!(Data.ecx & (1 << 5)))
		return FALSE;

	IA32_FEATURE_CONTROL_MSR Control = { 0 };
	Control.All = __readmsr(MSR_IA32_FEATURE_CONTROL);

	// Check for the BIOS lock

	if (Control.Fields.Lock == 0)
	{
		Control.Fields.Lock = TRUE;
		Control.Fields.EnableVmxon = TRUE;
		__writemsr(MSR_IA32_FEATURE_CONTROL, Control.All);
	}
	else if (Control.Fields.EnableVmxon == FALSE)
	{
		DbgPrint("[*] VMX locked in BIOS");
		return FALSE;
	}

	return TRUE;
}