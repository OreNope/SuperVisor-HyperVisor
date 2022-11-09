PUBLIC AsmEnableVmx

.code _text


AsmEnableVmx PROC PUBLIC

	PUSH RAX

	XOR RAX, RAX
	mov RAX, CR4

	OR RAX, 2000h	; Turn on the 14th bit (index 13)
	MOV CR4, RAX

	POP RAX
	RET

AsmEnableVmx ENDP


END