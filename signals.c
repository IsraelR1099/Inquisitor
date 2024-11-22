#include "inquisitor.h"

void	sigint_handler(int signum)
{
	(void)signum;
	if (sock >= 0)
		close(sock);
	printf("\n");
	exit(0);
}
