PUBLIC AsmEnableVmxeBit

.code _text


AsmEnableVmxeBit PROC PUBLIC

	PUSH RAX

	XOR RAX, RAX
	mov RAX, CR4

	OR RAX, 2000h	; Turn on the 14th bit (index 13)
	MOV CR4, RAX

	POP RAX
	RET

AsmEnableVmxeBit ENDP


END