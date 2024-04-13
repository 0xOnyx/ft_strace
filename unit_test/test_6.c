#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>

int main(){
    open("/foo/bar", O_RDONLY);
    return (0);
}