PUBLIC AsmEnableVmxeBit
PUBLIC AsmSaveStateForVmxoff
PUBLIC AsmVmxoffAndRestoreState

PUBLIC GetCs
PUBLIC GetDs
PUBLIC GetSs
PUBLIC GetEs
PUBLIC GetFs
PUBLIC GetGs
PUBLIC GetLdtr
PUBLIC GetTr
PUBLIC GetGdtBase
PUBLIC GetIdtBase
PUBLIC GetGdtLimit
PUBLIC GetIdtLimit
PUBLIC GetRflags

EXTERN g_StackPointer:QWORD
EXTERN g_BasePointer:QWORD

.code _text


AsmEnableVmxeBit PROC PUBLIC

	push rax

	xor rax, rax
	mov rax, cr4

	or rax, 2000h	; Turn on the 14th bit (index 13)
	mov cr4, rax
	
	pop rax
	ret

AsmEnableVmxeBit ENDP

AsmSaveStateForVmxoff PROC PUBLIC

	mov g_StackPointer, rsp
	mov g_BasePointer, rbp
	ret

AsmSaveStateForVmxoff ENDP

AsmVmxoffAndRestoreState PROC PUBLIC

	vmxoff

	mov rsp, g_StackPointer
	mov rbp, g_BasePointer

	add rsp, 8

	mov rax, 1

	mov rbx, [rsp + 28h + 8h]
	mov rsi, [rsp + 28h + 10h]
	add rsp, 20h
	pop rdi

	ret

AsmVmxoffAndRestoreState ENDP

GetGdtBase PROC PUBLIC

	local gdtr[10]:BYTE
	sgdt gdtr
	mov rax, QWORD PTR gdtr[2]

	ret

GetGdtBase ENDP

GetCs PROC PUBLIC

	mov rax, cs
	ret

GetCs ENDP

GetDs PROC PUBLIC

	mov rax, ds
	ret

GetDs ENDP

GetSs PROC PUBLIC

	mov rax, ss
	ret

GetSs ENDP

GetEs PROC PUBLIC

	mov rax, es
	ret

GetEs ENDP

GetFs PROC PUBLIC

	mov rax, fs
	ret

GetFs ENDP

GetGs PROC PUBLIC

	mov rax, gs
	ret

GetGs ENDP

GetLdtr PROC PUBLIC

	sldt rax
	ret

GetLdtr ENDP

GetTr PROC PUBLIC

	str rax
	ret

GetTr ENDP

GetIdtBase PROC PUBLIC
	
	local	idtr[10]:BYTE

	sidt idtr
	mov rax, QWORD PTR idtr[2]
	ret

GetIdtBase ENDP

GetGdtLimit PROC PUBLIC
	
	local gdtr[10]:BYTE

	sgdt gdtr
	mov ax, WORD PTR gdtr[0]
	ret

GetGdtLimit ENDP

GetIdtLimit PROC PUBLIC

	local	idtr[10]:BYTE
	
	sidt	idtr
	mov		ax, WORD PTR idtr[0]

	ret

GetIdtLimit ENDP

GetRflags PROC PUBLIC

	pushfq
	pop		rax
	ret

GetRflags ENDP

END