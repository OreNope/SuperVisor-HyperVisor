#pragma once

// Extern from Assembly.asm file


extern void inline AsmVmexitHandler(void);
extern void inline VmxSaveState(ULONG ProcessorID, PEPTP EPTP);
extern void inline VmxRestoreState();
extern void inline VmxoffHandler();

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

typedef union SEGMENT_ATTRIBUTES
{
    USHORT UCHARs;
    struct
    {
        USHORT TYPE : 4; /* 0;  Bit 40-43 */
        USHORT S : 1;    /* 4;  Bit 44 */
        USHORT DPL : 2;  /* 5;  Bit 45-46 */
        USHORT P : 1;    /* 7;  Bit 47 */

        USHORT AVL : 1; /* 8;  Bit 52 */
        USHORT L : 1;   /* 9;  Bit 53 */
        USHORT DB : 1;  /* 10; Bit 54 */
        USHORT G : 1;   /* 11; Bit 55 */
        USHORT GAP : 4;

    } Fields;
} SEGMENT_ATTRIBUTES;

typedef struct SEGMENT_SELECTOR
{
    USHORT             SEL;
    SEGMENT_ATTRIBUTES ATTRIBUTES;
    ULONG32            LIMIT;
    ULONG64            BASE;
} SEGMENT_SELECTOR, * PSEGMENT_SELECTOR;

typedef struct _SEGMENT_DESCRIPTOR
{
    USHORT LIMIT0;
    USHORT BASE0;
    UCHAR  BASE1;
    UCHAR  ATTR0;
    UCHAR  LIMIT1ATTR1;
    UCHAR  BASE2;
} SEGMENT_DESCRIPTOR, * PSEGMENT_DESCRIPTOR;

enum SEGREGS
{
    ES = 0,
    CS,
    SS,
    DS,
    FS,
    GS,
    LDTR,
    TR
};

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
    };

    ULONG64 Content;
} RFLAGS;