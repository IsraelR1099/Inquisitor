#include "inquisitor.h"

void	sigint_handler(int signum)
{
	(void)signum;
	if (sock >= 0)
		close(sock);
	stop = 1;
	printf("SIGINT received, exiting...\n");
	printf("\n");
	exit(0);
}
