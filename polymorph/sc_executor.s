#################### DEFINES ####################
#   Register aliases - x64 syscall convention	#
.set	r_syscall,	%rax
.set	r_arg1,		%rdi
.set	r_arg2,		%rsi
.set	r_arg3,		%rdx
.set	r_ret,		%rax		# unused
.set	r_retb,		%al		# unused

#	<unistd.h> syscall constants - x64	#
.set	SYS_READ,	0		# unused
.set	SYS_WRITE,	1
.set	SYS_OPEN,	2		# unused
.set	SYS_CLOSE,	3		# unused
.set	SYS_EXIT,	60

#		File descriptors		#
.set	STDIN,		0		# unused
.set	STDOUT,		1
.set	STDERR,		2

#		Custom constants		#
.set	BUFSIZE,	100

#################################################



#################### STRINGS ####################
.section .rodata
title:
	.ascii "===== Shellcode Executor =====\n"
	titlelen = . - title

usage:
	.ascii "Usage:\n"
	usagelen = . - usage

usage2:
	.ascii " <shellcode>\n"
	.ascii "\n"
	.ascii "The shellcode cannot be longer than 100 bytes\n"
	.ascii "and must not contain any of the following bytes:\n"
	.ascii " > '/', 'b', 'i', 'n', 's', 'h'\n"
	.ascii " > whitespaces\n"
	.ascii " > those in x86_64 syscalls (0x80cd, 0x050f, 0x340f)\n"
	.ascii "The null byte ('\\0') is only allowed as the last byte; "
	.ascii "else it might get skipped.\n"
	usage2len = . - usage2

abort:
	.ascii "Failure, the shellcode contains a forbidden char!\n"
	.ascii "(Tip: you can use 'echo $?' to know its index)\n"
	abortlen = . - abort

abort2:
	.ascii "Failure, the shellcode is too long (100 bytes max.)\n"
	abort2len = . - abort
#################################################



#################### MACROS #####################
#		1: S-mov			#
.macro	smov	src, dst
	push	\src
	pop	\dst
.endm

#		2: Syscall			#
.macro	_syscall
	syscall
.endm

#		3: cmpchk			#
.macro	cmpbchk	arg
	cmpb	\arg,		(%rsi, %rcx)
	je	invalid_char
.endm
.macro	cmpwchk	arg
	cmpw	\arg,		(%rsi, %rcx)
	je	invalid_char
.endm
#################################################


##################### CODE ######################
.text
.globl _start
_start:
	# puts(title);	/* a.k.a Hello world! */
	smov	$SYS_WRITE,	r_syscall
	smov	$STDOUT,	r_arg1
	lea	title(%rip),	r_arg2
	smov	$titlelen,	r_arg3
	_syscall

	/* Check argc */
	cmpb	$2, (%rsp)
	jne	_usage

	/* argv[1] -> the shellcode */
	mov	0x10(%rsp),	%rsi
	xor	%rcx,		%rcx	# %rcx <-> size_t i = 0;
	xor	%ebx,		%ebx	# %ebx <-> bool got_null = 0;

scan_or_clear:
	test	%ebx,		%ebx
	jz	scan			# !got_null => jumpto scan;

clear:
	movb	$0,		(%rsi, %rcx)
	jmp	gonext

scan:
	cmpbchk	$0x08		# '\b'
	cmpbchk	$0x09		# '\t'
	cmpbchk	$0x0a		# '\n'
	cmpbchk	$0x0d		# '\r'
	cmpbchk	$0x20		# ' '
	cmpbchk	$0x2f		# '/'
	cmpbchk	$0x62		# 'b'
	cmpbchk	$0x69		# 'i'
	cmpbchk	$0x6e		# 'n'
	cmpbchk	$0x73		# 's'
	cmpbchk	$0x68		# 'h'
	cmpwchk	$0x80cd 	# x86-syscall
	cmpwchk	$0x050f 	# x64-syscall
	cmpwchk	$0x340f 	# sysenter

scan_null:
/* Encountered null char => set %ebx = 1 (and clear all bytes following it) */
	cmpb	$0,		(%rsi, %rcx)
	jne	gonext
	inc	%ebx		# got_null = 1;

gonext:
	inc	%rcx
	cmpb	$BUFSIZE,	%cl
	jbe	scan_or_clear		# do {...} while (i <= BUFSIZE);

/* At this point, we have analyzed BUFSIZE + 1 bytes.
   If the shellcode truly is less than BUFSIZE bytes long,
   we should have encountered its '\0'-null terminator byte by now... */
	test	%ebx,		%ebx
	jz	too_long		# !got_null => shellcode too long

/* Execute shellcode */
	jmp	*%rsi

invalid_char:
	push	%rcx			# i = index of the 1st invalid char #

	# fputs(abort, stderr);
	smov	$SYS_WRITE, 	r_syscall
	smov	$STDERR,	r_arg1
	lea	abort(%rip),	r_arg2
	smov	$abortlen,	r_arg3
	_syscall

	# _exit(i);
	smov	$SYS_EXIT,	r_syscall
	pop	r_arg1
	_syscall

too_long:
	# fputs(abort2, stderr);
	push	%rcx
	smov	$SYS_WRITE, 	r_syscall
	smov	$STDERR,	r_arg1
	lea	abort2(%rip),	r_arg2
	smov	$abort2len,	r_arg3
	_syscall

	# _exit(1)
	smov	$SYS_EXIT,	r_syscall
	smov	$1,		r_arg1
	_syscall

_usage: /* fprintf(stderr, "%s%s%s", usage, argv[0], usage2); */
	# fputs(usage, stderr);
	smov	$SYS_WRITE,	r_syscall
	smov	$STDERR,	r_arg1
	lea	usage(%rip),	r_arg2
	smov	$usagelen,	r_arg3
	_syscall

	# fputs(argv[0], stderr);
	smov	$SYS_WRITE,	r_syscall
	smov	$STDERR,	r_arg1
	mov	0x8(%rsp),	r_arg2
	xor	r_arg3, 	r_arg3
	inc	r_arg3
	cmpb	$0,		(r_arg2, r_arg3)
	jne	. - 7
	_syscall

	# fputs(usage2, stderr);
	smov	$SYS_WRITE,	r_syscall
	smov	$STDERR,	r_arg1
	lea	usage2(%rip),	r_arg2
	smov	$usage2len,	r_arg3
	_syscall

	# _exit(1);
	smov	$SYS_EXIT,	r_syscall
	smov	$1,		r_arg1
	_syscall
#################################################

# executable stack - (is it as effective as '-z execstack'?)
.section    .note.GNU-stack,	"x",	@progbits
