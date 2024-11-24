#include "inquisitor.h"

void	sigint_handler(int signum)
{
	(void)signum;
	printf("SIGINT received, exiting...\n");
	if (sock >= 0)
	{
		printf("Closing socket...\n");
		close(sock);
		sock = -1;
	}
}
