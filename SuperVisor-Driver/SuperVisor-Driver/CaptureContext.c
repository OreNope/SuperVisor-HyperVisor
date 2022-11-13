#include "CaptureContext.h"
#include <ntifs.h>

void MyCaptureContext(void* ContextRecord)
{
	RtlCaptureContext((PCONTEXT)ContextRecord);
}
