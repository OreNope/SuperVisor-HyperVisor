#pragma once
#include <poppack.h>
#include <pshpack1.h>
#include <basetsd.h>

// Extern from Assembly.asm file

extern void inline AsmVmexitHandler(void);
extern void inline VmxSaveState(ULONG ProcessorID, PVOID EPTP);
extern void inline VmxRestoreState();
extern void inline VmxoffHandler();

extern ULONG64 inline MSRRead(ULONG32 reg);
extern void inline MSRWrite(ULONG32 reg, ULONG64 MsrValue);

extern void inline AsmEnableVmxeBit(void);
extern void inline AsmSaveStateForVmxoff(void);
extern void inline AsmVmxoffAndRestoreState(void);
extern void inline AsmEnableVmxeBit(void);

extern USHORT inline GetCs();
extern USHORT inline GetDs();
extern USHORT inline GetSs();
extern USHORT inline GetEs();
extern USHORT inline GetFs();
extern USHORT inline GetGs();
extern USHORT inline GetLdtr();
extern USHORT inline GetTr();
extern ULONG64 inline GetGdtBase();
extern ULONG64 inline GetIdtBase();
extern USHORT inline GetGdtLimit();
extern USHORT inline GetIdtLimit();
extern ULONG64 inline GetRflags();

typedef struct _DESCRIPTOR_TABLE_REGISTER
{
    UINT16 Limit;
    ULONG_PTR Base;
} DESCRIPTOR_TABLE_REGISTER, * PDESCRIPTOR_TABLE_REGISTER;

typedef struct _SEGMENT_DESCRIPTOR
{
    union
    {
        UINT64 AsUInt64;
        struct
        {
            UINT16 LimitLow;        // [0:15]
            UINT16 BaseLow;         // [16:31]
            UINT32 BaseMiddle : 8;  // [32:39]
            UINT32 Type : 4;        // [40:43]
            UINT32 System : 1;      // [44]
            UINT32 Dpl : 2;         // [45:46]
            UINT32 Present : 1;     // [47]
            UINT32 LimitHigh : 4;   // [48:51]
            UINT32 Avl : 1;         // [52]
            UINT32 LongMode : 1;    // [53]
            UINT32 DefaultBit : 1;  // [54]
            UINT32 Granularity : 1; // [55]
            UINT32 BaseHigh : 8;    // [56:63]
        } Fields;
    };
} SEGMENT_DESCRIPTOR, * PSEGMENT_DESCRIPTOR;


typedef struct _SEGMENT_ATTRIBUTE
{
    union
    {
        UINT16 AsUInt16;
        struct
        {
            UINT16 Type : 4;        // [0:3]
            UINT16 System : 1;      // [4]
            UINT16 Dpl : 2;         // [5:6]
            UINT16 Present : 1;     // [7]
            UINT16 Avl : 1;         // [8]
            UINT16 LongMode : 1;    // [9]
            UINT16 DefaultBit : 1;  // [10]
            UINT16 Granularity : 1; // [11]
            UINT16 Reserved1 : 4;   // [12:15]
        } Fields;
    };
} SEGMENT_ATTRIBUTE, * PSEGMENT_ATTRIBUTE;

typedef struct _GUEST_REGS
{
    ULONG64 rax; // 0x00         // NOT VALID FOR SVM
    ULONG64 rcx;
    ULONG64 rdx; // 0x10
    ULONG64 rbx;
    ULONG64 rsp; // 0x20         // rsp is not stored here on SVM
    ULONG64 rbp;
    ULONG64 rsi; // 0x30
    ULONG64 rdi;
    ULONG64 r8; // 0x40
    ULONG64 r9;
    ULONG64 r10; // 0x50
    ULONG64 r11;
    ULONG64 r12; // 0x60
    ULONG64 r13;
    ULONG64 r14; // 0x70
    ULONG64 r15;
} GUEST_REGS, * PGUEST_REGS;

typedef union _RFLAGS
{
    struct
    {
        unsigned Reserved1 : 10;
        unsigned ID : 1;  // Identification flag
        unsigned VIP : 1; // Virtual interrupt pending
        unsigned VIF : 1; // Virtual interrupt flag
        unsigned AC : 1;  // Alignment check
        unsigned VM : 1;  // Virtual 8086 mode
        unsigned RF : 1;  // Resume flag
        unsigned Reserved2 : 1;
        unsigned NT : 1;   // Nested task flag
        unsigned IOPL : 2; // I/O privilege level
        unsigned OF : 1;
        unsigned DF : 1;
        unsigned IF : 1; // Interrupt flag
        unsigned TF : 1; // Task flag
        unsigned SF : 1; // Sign flag
        unsigned ZF : 1; // Zero flag
        unsigned Reserved3 : 1;
        unsigned AF : 1; // Borrow flag
        unsigned Reserved4 : 1;
        unsigned PF : 1; // Parity flag
        unsigned Reserved5 : 1;
        unsigned CF : 1; // Carry flag [Bit 0]
        unsigned Reserved6 : 32;
    } Fields;

    ULONG64 Content;
} RFLAGS;
