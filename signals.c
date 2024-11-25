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
		stop = 1;
		printf("Setting stop to 1\n");
		if (handle != NULL)
		{
			printf("Breaking pcap lopp...\n");
			pcap_breakloop(handle);
		}
	}
}
