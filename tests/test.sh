#!/bin/bash
xxd -i lol | sed 1d | sed '$d' | sed '$d' | xargs echo -n | tr -d '\n' | sed '1s/^/[/' | sed "$ s/$/]\n/"
