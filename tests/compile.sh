#!/bin/bash
/usr/bin/nasm shellcode.asm
xxd -i shellcode | sed 1d | sed '$d' | sed '$d' | xargs echo -n | tr -d '\n' | sed '1s/^/[/' | sed "$ s/$/]\n/"
