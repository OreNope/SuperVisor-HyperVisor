#pragma once
#include <ntddk.h>
#include <wdf.h>
#include <wdm.h>
#include <intrin.h>
#include "AMDMSR.h"
#include "Assembly.h"
#include "SLAT.h"
#include "VMCB.h"
#include "Memory.h"

#define ALIGNMENT_PAGE_SIZE 4096
#define MAXIMUM_ADDRESS     0xffffffffffffffff
#define VMCS_SIZE           4096
#define VMM_STACK_SIZE      0x8000
#define RPL_MASK            3
#define VMXON_SIZE          4096

#define DPL_USER   3
#define DPL_SYSTEM 0

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

BOOLEAN InitializeSvm();
UINT16 GetSegmentAccessRight(_In_ UINT16 SegmentSelector, _In_ ULONG_PTR GdtBase);
VOID TerminateVmx();
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
ULONG AdjustControls(ULONG Ctl, ULONG Msr);
