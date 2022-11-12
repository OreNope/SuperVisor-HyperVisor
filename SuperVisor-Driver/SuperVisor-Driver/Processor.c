#include "Processor.h"
#include <intrin.h>
#include "AMDMSR.h"


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

BOOLEAN IsSvmSupported()
{
	CPUID Data = { 0 };

    // Test if the current processor is AMD one. (AuthenticAMD)
    __cpuid((int*)&Data, CPUID_MAX_STANDARD_FN_NUMBER_AND_VENDOR_STRING);
    if ((Data.ebx != 'htuA') ||
        (Data.edx != 'itne') ||
        (Data.ecx != 'DMAc'))
    {
        return FALSE;
    }

    // Test if the SVM feature is supported by the current processor. See
    __cpuid((int*)&Data, CPUID_PROCESSOR_AND_PROCESSOR_FEATURE_IDENTIFIERS_EX);
    if ((Data.ecx & CPUID_FN8000_0001_ECX_SVM) == 0)
        return FALSE;

    // Test if the Nested Page Tables feature is supported by the current processor.
    __cpuid((int*)&Data, CPUID_SVM_FEATURES);
    if ((Data.edx & CPUID_FN8000_000A_EDX_NP) == 0)
        return FALSE;

    // When VM_CR.SVMDIS is set, EFER.SVME cannot be 1, therefore, SVM cannot be enabled.
    ULONG64 vmcr = __readmsr(SVM_MSR_VM_CR);
    if ((vmcr & SVM_VM_CR_SVMDIS) != 0)
        return FALSE;


	return TRUE;
}