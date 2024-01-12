#include <stddef.h>

#include <stdio.h>

int BIG_INT = 0;

long asstrace_read(unsigned int fd, char *buf, size_t count);

int main() {
	asstrace_read(0,NULL,0);
	
	BIG_INT = 111;
	asstrace_read(0,NULL,0);

	return 0 ;
}
