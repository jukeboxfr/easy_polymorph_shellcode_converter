#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
int
main(int argc, char *argv[]) {
	int	(*shell)();
	char	*shellcode;
	size_t	size;

	if (argc != 2) {
		printf("Usage: ./test <shellcode>\n");
		fflush(stdout);	
		return (0);
	}
	(void)argv;
	size = strlen(argv[1]);
	shellcode = malloc(sizeof(char) * size);
	strncpy(shellcode, argv[1], size);
	shell = (int(*)())shellcode;
	shell();
	return (0);
}
