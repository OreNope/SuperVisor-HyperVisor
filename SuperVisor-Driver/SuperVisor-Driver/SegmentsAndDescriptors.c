#include "SegmentsAndDescriptors.h"

UINT16 GetSegmentAccessRight(_In_ UINT16 SegmentSelector, _In_ ULONG_PTR GdtBase)
{
    PSEGMENT_DESCRIPTOR descriptor;
    SEGMENT_ATTRIBUTE attribute;

    // Get a segment descriptor corresponds to the specified segment selector.
    descriptor = (PSEGMENT_DESCRIPTOR)(GdtBase + (SegmentSelector & ~RPL_MASK));

    attribute.Fields.Type = descriptor->Fields.Type;
    attribute.Fields.System = descriptor->Fields.System;
    attribute.Fields.Dpl = descriptor->Fields.Dpl;
    attribute.Fields.Present = descriptor->Fields.Present;
    attribute.Fields.Avl = descriptor->Fields.Avl;
    attribute.Fields.LongMode = descriptor->Fields.LongMode;
    attribute.Fields.DefaultBit = descriptor->Fields.DefaultBit;
    attribute.Fields.Granularity = descriptor->Fields.Granularity;
    attribute.Fields.Reserved1 = 0;

    return attribute.AsUInt16;
}
