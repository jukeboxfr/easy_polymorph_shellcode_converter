#!/usr/bin/python3
import	sys
import	os
import	subprocess
from termcolor import	colored
from subprocess import	Popen, PIPE

filters = [0x08, 0x09, 0x0a, 0x0d, 0x20, 0x2f, 0x62, 0x69, 0x6e, 0x73, 0x68, 0x80cd, 0x050f, 0x340f]

if len(sys.argv) != 2:
	print(colored("Usage: encode <shellcode>", "red"))
	sys.exit(0)
shellcode = sys.argv[1]
shellcode_len = len(shellcode)

def	print_decoder(shellcode):
	f = open("decoder.asm", "w")
	f.write("""BITS 64
jmp short foo
bar:
	pop rsi
	xor rcx, rcx
	mov rcx, {}
decoder:
	sub byte [esi + ecx - 1], 0
	sub rcx, 1
	jnz decoder
	jmp short shellcode
foo:
	call bar
shellcode:
	""".format(shellcode_len))
	f.close()
	os.system("nasm decoder.asm")
	result = subprocess.Popen(['xxd -ps decoder'], shell=True, stdout=subprocess.PIPE).communicate()[0]
	result = result.decode("utf-8").replace("\n", "")
	print(result)
#def	print_shellcode(shellcode):

print_decoder(shellcode)
#print_shellcode(shellcode)
