#include "Processor.h"
#include <intrin.h>
#include "IntelMSR.h"


BOOLEAN RunOnProcessor(ULONG ProcessorNumber, PEPTP EPTP, PFUNC Routine)
{
	KIRQL OldIrql;

	KeSetSystemAffinityThread((KAFFINITY)(1 << ProcessorNumber));

	OldIrql = KeRaiseIrqlToDpcLevel();

	Routine(ProcessorNumber, EPTP);

	KeLowerIrql(OldIrql);

	KeRevertToUserAffinityThread();

	return TRUE;
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