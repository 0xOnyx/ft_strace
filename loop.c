#include <unistd.h>
#include <stdio.h>
#include <signal.h>


static void sig(int sig){
	printf("[+]\tnew signal=> %d\n", sig); 
	write(1, "a", 1);
}

int	main(){
	printf("value of pid => %d\n", getpid());
//	signal(SIGTERM, sig);
	while(1){
		sleep(3);		
	}
	return (10);
}
