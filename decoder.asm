BITS 64
jmp short foo
bar:
	pop rsi
	xor rcx, rcx
	mov rcx, 3
decoder:
	sub byte [esi + ecx - 1], 0
	sub rcx, 1
	jnz decoder
	jmp short shellcode
foo:
	call bar
shellcode:
	