#!/usr/bin/python3
import sys
from termcolor import colored

filters = [0x08, 0x09, 0x0a, 0x0d, 0x20, 0x2f, 0x62, 0x69, 0x6e, 0x73, 0x68, 0x80cd, 0x050f, 0x340f]

if len(sys.argv) != 2:
	print("Usage: shellcode <file>")	
	sys.exit(0)
try:
	f = open(sys.argv[1], "r")
except:
	print("Impossible to open the file")
	sys.exit(0)
content = f.read()
f.close()
success = 1
for c in filters:
	if content.find(str(c)) != -1:
		print("The shellcode contains an unauthorized character:", hex(c))
		success = 0
		break ;
if success != 1:
	print(colored("KO", "red"));
else:
	print(colored("size: {}".format(len(content)), "yellow")) 
	print(colored("OK", "green"));
