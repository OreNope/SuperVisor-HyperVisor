#pragma once
#include <ntddk.h>
#include <wdf.h>
#include <wdm.h>
#include <intrin.h>
#include "AMDMSR.h"
#include "Assembly.h"
#include "SLAT.h"

#define ALIGNMENT_PAGE_SIZE 4096
#define MAXIMUM_ADDRESS     0xffffffffffffffff
#define VMCS_SIZE           4096
#define VMM_STACK_SIZE      0x8000
#define RPL_MASK            3
#define VMXON_SIZE          4096

#define DPL_USER   3
#define DPL_SYSTEM 0

typedef struct _VMCB_CONTROL_AREA
{
    UINT16 InterceptCrRead;             // +0x000
    UINT16 InterceptCrWrite;            // +0x002
    UINT16 InterceptDrRead;             // +0x004
    UINT16 InterceptDrWrite;            // +0x006
    UINT32 InterceptException;          // +0x008
    UINT32 InterceptMisc1;              // +0x00c
    UINT32 InterceptMisc2;              // +0x010
    UINT8 Reserved1[0x03c - 0x014];     // +0x014
    UINT16 PauseFilterThreshold;        // +0x03c
    UINT16 PauseFilterCount;            // +0x03e
    UINT64 IopmBasePa;                  // +0x040
    UINT64 MsrpmBasePa;                 // +0x048
    UINT64 TscOffset;                   // +0x050
    UINT32 GuestAsid;                   // +0x058
    UINT32 TlbControl;                  // +0x05c
    UINT64 VIntr;                       // +0x060
    UINT64 InterruptShadow;             // +0x068
    UINT64 ExitCode;                    // +0x070
    UINT64 ExitInfo1;                   // +0x078
    UINT64 ExitInfo2;                   // +0x080
    UINT64 ExitIntInfo;                 // +0x088
    UINT64 NpEnable;                    // +0x090
    UINT64 AvicApicBar;                 // +0x098
    UINT64 GuestPaOfGhcb;               // +0x0a0
    UINT64 EventInj;                    // +0x0a8
    UINT64 NCr3;                        // +0x0b0
    UINT64 LbrVirtualizationEnable;     // +0x0b8
    UINT64 VmcbClean;                   // +0x0c0
    UINT64 NRip;                        // +0x0c8
    UINT8 NumOfBytesFetched;            // +0x0d0
    UINT8 GuestInstructionBytes[15];    // +0x0d1
    UINT64 AvicApicBackingPagePointer;  // +0x0e0
    UINT64 Reserved2;                   // +0x0e8
    UINT64 AvicLogicalTablePointer;     // +0x0f0
    UINT64 AvicPhysicalTablePointer;    // +0x0f8
    UINT64 Reserved3;                   // +0x100
    UINT64 VmcbSaveStatePointer;        // +0x108
    UINT8 Reserved4[0x400 - 0x110];     // +0x110
} VMCB_CONTROL_AREA, *PVMCB_CONTROL_AREA;

// See "VMCB Layout, State Save Area"
typedef struct _VMCB_STATE_SAVE_AREA
{
    UINT16 EsSelector;                  // +0x000
    UINT16 EsAttrib;                    // +0x002
    UINT32 EsLimit;                     // +0x004
    UINT64 EsBase;                      // +0x008
    UINT16 CsSelector;                  // +0x010
    UINT16 CsAttrib;                    // +0x012
    UINT32 CsLimit;                     // +0x014
    UINT64 CsBase;                      // +0x018
    UINT16 SsSelector;                  // +0x020
    UINT16 SsAttrib;                    // +0x022
    UINT32 SsLimit;                     // +0x024
    UINT64 SsBase;                      // +0x028
    UINT16 DsSelector;                  // +0x030
    UINT16 DsAttrib;                    // +0x032
    UINT32 DsLimit;                     // +0x034
    UINT64 DsBase;                      // +0x038
    UINT16 FsSelector;                  // +0x040
    UINT16 FsAttrib;                    // +0x042
    UINT32 FsLimit;                     // +0x044
    UINT64 FsBase;                      // +0x048
    UINT16 GsSelector;                  // +0x050
    UINT16 GsAttrib;                    // +0x052
    UINT32 GsLimit;                     // +0x054
    UINT64 GsBase;                      // +0x058
    UINT16 GdtrSelector;                // +0x060
    UINT16 GdtrAttrib;                  // +0x062
    UINT32 GdtrLimit;                   // +0x064
    UINT64 GdtrBase;                    // +0x068
    UINT16 LdtrSelector;                // +0x070
    UINT16 LdtrAttrib;                  // +0x072
    UINT32 LdtrLimit;                   // +0x074
    UINT64 LdtrBase;                    // +0x078
    UINT16 IdtrSelector;                // +0x080
    UINT16 IdtrAttrib;                  // +0x082
    UINT32 IdtrLimit;                   // +0x084
    UINT64 IdtrBase;                    // +0x088
    UINT16 TrSelector;                  // +0x090
    UINT16 TrAttrib;                    // +0x092
    UINT32 TrLimit;                     // +0x094
    UINT64 TrBase;                      // +0x098
    UINT8 Reserved1[0x0cb - 0x0a0];     // +0x0a0
    UINT8 Cpl;                          // +0x0cb
    UINT32 Reserved2;                   // +0x0cc
    UINT64 Efer;                        // +0x0d0
    UINT8 Reserved3[0x148 - 0x0d8];     // +0x0d8
    UINT64 Cr4;                         // +0x148
    UINT64 Cr3;                         // +0x150
    UINT64 Cr0;                         // +0x158
    UINT64 Dr7;                         // +0x160
    UINT64 Dr6;                         // +0x168
    UINT64 Rflags;                      // +0x170
    UINT64 Rip;                         // +0x178
    UINT8 Reserved4[0x1d8 - 0x180];     // +0x180
    UINT64 Rsp;                         // +0x1d8
    UINT8 Reserved5[0x1f8 - 0x1e0];     // +0x1e0
    UINT64 Rax;                         // +0x1f8
    UINT64 Star;                        // +0x200
    UINT64 LStar;                       // +0x208
    UINT64 CStar;                       // +0x210
    UINT64 SfMask;                      // +0x218
    UINT64 KernelGsBase;                // +0x220
    UINT64 SysenterCs;                  // +0x228
    UINT64 SysenterEsp;                 // +0x230
    UINT64 SysenterEip;                 // +0x238
    UINT64 Cr2;                         // +0x240
    UINT8 Reserved6[0x268 - 0x248];     // +0x248
    UINT64 GPat;                        // +0x268
    UINT64 DbgCtl;                      // +0x270
    UINT64 BrFrom;                      // +0x278
    UINT64 BrTo;                        // +0x280
    UINT64 LastExcepFrom;               // +0x288
    UINT64 LastExcepTo;                 // +0x290
} VMCB_STATE_SAVE_AREA, * PVMCB_STATE_SAVE_AREA;

// An entire VMCB (Virtual machine control block) layout.
typedef struct _VMCB
{
    VMCB_CONTROL_AREA ControlArea;
    VMCB_STATE_SAVE_AREA StateSaveArea;
    UINT8 Reserved1[0x1000 - sizeof(VMCB_CONTROL_AREA) - sizeof(VMCB_STATE_SAVE_AREA)];
} VMCB, *PVMCB;

typedef struct _VIRTUAL_PROCESSOR_DATA
{
    union
    {
        DECLSPEC_ALIGN(PAGE_SIZE) UINT8 HostStackLimit[KERNEL_STACK_SIZE];
        struct
        {
            UINT8 StackContents[KERNEL_STACK_SIZE - (sizeof(PVOID) * 6) - sizeof(KTRAP_FRAME)];
            KTRAP_FRAME TrapFrame;
            UINT64 GuestVmcbPa;     // HostRsp
            UINT64 HostVmcbPa;
            struct _VIRTUAL_PROCESSOR_DATA* Self;
            PSHARED_VIRTUAL_PROCESSOR_DATA SharedVpData;
            UINT64 Padding1;        // To keep HostRsp 16 bytes aligned
            UINT64 Reserved1;
        } HostStackLayout;
    };

    DECLSPEC_ALIGN(PAGE_SIZE) VMCB GuestVmcb;
    DECLSPEC_ALIGN(PAGE_SIZE) VMCB HostVmcb;
    DECLSPEC_ALIGN(PAGE_SIZE) UINT8 HostStateArea[PAGE_SIZE];
} VIRTUAL_PROCESSOR_DATA, *PVIRTUAL_PROCESSOR_DATA;

// See "VMCB Layout, Control Area"
#define SVM_INTERCEPT_MISC1_CPUID       (1UL << 18)
#define SVM_INTERCEPT_MISC1_MSR_PROT    (1UL << 28)
#define SVM_INTERCEPT_MISC2_VMRUN       (1UL << 0)
#define SVM_NP_ENABLE_NP_ENABLE         (1UL << 0)

#define POOLTAG 0x53564856 // [S]uper[Visor] - [H]yper[V]isor (SVHV)

// PIN-Based Execution
#define PIN_BASED_VM_EXECUTION_CONTROLS_EXTERNAL_INTERRUPT        0x00000001
#define PIN_BASED_VM_EXECUTION_CONTROLS_NMI_EXITING               0x00000008
#define PIN_BASED_VM_EXECUTION_CONTROLS_VIRTUAL_NMI               0x00000020
#define PIN_BASED_VM_EXECUTION_CONTROLS_ACTIVE_VMX_TIMER          0x00000040
#define PIN_BASED_VM_EXECUTION_CONTROLS_PROCESS_POSTED_INTERRUPTS 0x00000080

#define CPU_BASED_VIRTUAL_INTR_PENDING        0x00000004
#define CPU_BASED_USE_TSC_OFFSETING           0x00000008
#define CPU_BASED_HLT_EXITING                 0x00000080
#define CPU_BASED_INVLPG_EXITING              0x00000200
#define CPU_BASED_MWAIT_EXITING               0x00000400
#define CPU_BASED_RDPMC_EXITING               0x00000800
#define CPU_BASED_RDTSC_EXITING               0x00001000
#define CPU_BASED_CR3_LOAD_EXITING            0x00008000
#define CPU_BASED_CR3_STORE_EXITING           0x00010000
#define CPU_BASED_CR8_LOAD_EXITING            0x00080000
#define CPU_BASED_CR8_STORE_EXITING           0x00100000
#define CPU_BASED_TPR_SHADOW                  0x00200000
#define CPU_BASED_VIRTUAL_NMI_PENDING         0x00400000
#define CPU_BASED_MOV_DR_EXITING              0x00800000
#define CPU_BASED_UNCOND_IO_EXITING           0x01000000
#define CPU_BASED_ACTIVATE_IO_BITMAP          0x02000000
#define CPU_BASED_MONITOR_TRAP_FLAG           0x08000000
#define CPU_BASED_ACTIVATE_MSR_BITMAP         0x10000000
#define CPU_BASED_MONITOR_EXITING             0x20000000
#define CPU_BASED_PAUSE_EXITING               0x40000000
#define CPU_BASED_ACTIVATE_SECONDARY_CONTROLS 0x80000000

#define CPU_BASED_CTL2_ENABLE_EPT                 0x2
#define CPU_BASED_CTL2_RDTSCP                     0x8
#define CPU_BASED_CTL2_ENABLE_VPID                0x20
#define CPU_BASED_CTL2_UNRESTRICTED_GUEST         0x80
#define CPU_BASED_CTL2_VIRTUAL_INTERRUPT_DELIVERY 0x200
#define CPU_BASED_CTL2_ENABLE_INVPCID             0x1000
#define CPU_BASED_CTL2_ENABLE_VMFUNC              0x2000
#define CPU_BASED_CTL2_ENABLE_XSAVE_XRSTORS       0x100000

// VM-exit Control Bits
#define VM_EXIT_IA32E_MODE       0x00000200
#define VM_EXIT_ACK_INTR_ON_EXIT 0x00008000
#define VM_EXIT_SAVE_GUEST_PAT   0x00040000
#define VM_EXIT_LOAD_HOST_PAT    0x00080000

// VM-entry Control Bits
#define VM_ENTRY_IA32E_MODE         0x00000200
#define VM_ENTRY_SMM                0x00000400
#define VM_ENTRY_DEACT_DUAL_MONITOR 0x00000800
#define VM_ENTRY_LOAD_GUEST_PAT     0x00004000

#define HYPERV_CPUID_VENDOR_AND_MAX_FUNCTIONS 0x40000000
#define HYPERV_CPUID_INTERFACE                0x40000001
#define HYPERV_CPUID_VERSION                  0x40000002
#define HYPERV_CPUID_FEATURES                 0x40000003
#define HYPERV_CPUID_ENLIGHTMENT_INFO         0x40000004
#define HYPERV_CPUID_IMPLEMENT_LIMITS         0x40000005

#define HYPERV_HYPERVISOR_PRESENT_BIT 0x80000000
#define HYPERV_CPUID_MIN              0x40000005
#define HYPERV_CPUID_MAX              0x4000ffff

// Exit Qualifications for MOV for Control Register Access
#define TYPE_MOV_TO_CR   0
#define TYPE_MOV_FROM_CR 1
#define TYPE_CLTS        2
#define TYPE_LMSW        3

UINT64 VirtualToPhysicalAddress(void* Va);
UINT64 PhysicalToVirtualAddress(UINT64 Pa);
BOOLEAN AllocateVmxonRegion(VIRTUAL_MACHINE_STATE* GuestState);
BOOLEAN AllocateVmcsRegion(VIRTUAL_MACHINE_STATE* GuestState);
BOOLEAN AllocateVmmStack(ULONG ProcessorID);
BOOLEAN AllocateMsrBitmap(ULONG ProcessorID);

BOOLEAN InitializeSvm();
void PrepareForVirtualization(_Inout_ PVIRTUAL_PROCESSOR_DATA VpData, _In_ PSHARED_VIRTUAL_PROCESSOR_DATA SharedVpData, _In_ const CONTEXT* ContextRecord);
UINT16 GetSegmentAccessRight(_In_ UINT16 SegmentSelector, _In_ ULONG_PTR GdtBase);
void TerminateVmx();
void VirtualizeCurrentSystem(ULONG ProcessorID, PEPTP EPTP, PVOID GuestStack);
BOOLEAN SetupVmcsAndVirtualizeMachine(VIRTUAL_MACHINE_STATE* GuestState, PEPTP EPTP, PVOID GuestStack);
BOOLEAN SetTargetControls(UINT64 CR3, UINT64 Index);
VOID MainVmexitHandler(PGUEST_REGS GuestRegs);
BOOLEAN HandleCPUID(PGUEST_REGS state);
VOID HandleControlRegisterAccess(PGUEST_REGS GuestState);
VOID HandleMSRRead(PGUEST_REGS GuestRegs);
VOID HandleMSRWrite(PGUEST_REGS GuestRegs);
VOID SetBit(PVOID Addr, UINT64 Bit, BOOLEAN Set);
VOID GetBit(PVOID Addr, UINT64 Bit);
BOOLEAN SetMsrBitmap(ULONG64 Msr, int ProcessID, BOOLEAN ReadDetection, BOOLEAN WriteDetection);
VOID VmResumeInstruction();
VOID GuestSkipToNextInstruction();
void FillGuestSelectorData(PVOID GdtBase, ULONG segreg, USHORT Selector);
BOOLEAN GetSegmentDescriptor(PSEGMENT_SELECTOR SegmentSelector, USHORT Selector, PUCHAR GdtBase);
ULONG AdjustControls(ULONG Ctl, ULONG Msr);
UINT64 VmptrstInstruction();
BOOLEAN ClearVmcsState(VIRTUAL_MACHINE_STATE* GuestState);
BOOLEAN LoadVmcs(VIRTUAL_MACHINE_STATE* GuestState);
