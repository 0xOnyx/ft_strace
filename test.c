
#include <stdio.h>
#include <unistd.h>

int	main(int argc, char **argv){
	printf("value of argv=>%s\n", argv[0]); 
	write(STDOUT_FILENO, "test\n", 5);
	return (0);
}
