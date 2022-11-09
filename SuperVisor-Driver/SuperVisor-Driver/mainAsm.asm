PUBLIC AsmEnableVmxOperation

.code _text


AsmEnableVmxOperation PROC PUBLIC

	PUSH RAX

	XOR RAX, RAX
	mov RAX, CR4

	OR RAX, 2000h	; Turn on the 14th bit
	MOV CR4, RAX

	POP RAX
	RET

AsmEnableVmxOperation ENDP


END