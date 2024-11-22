/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   utils.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: irifarac <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/11/22 11:54:49 by irifarac          #+#    #+#             */
/*   Updated: 2024/11/22 12:03:12 by irifarac         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "inquisitor.h"

void	usage(void)
{
	fprintf(stderr, "Usage: ./arp-spoof [-h] [-i interface] [-v]\n");
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "  -h\t\tPrint this help message\n");
	fprintf(stderr, "  -i interface\tSpecify the interface to use\n");
	fprintf(stderr, "  -v\t\tVerbose mode\n");
}

void	get_gateway(char *gateway_ip)
{
	FILE			*fp;
	char			buf[256];
	char			iface[16];
	unsigned long	dest;
	unsigned long	gw;
	struct in_addr	gw_addr;

	fp = fopen("/proc/net/route", "r");
	if (fp == NULL)
	{
		perror("fopen");
		exit(1);
	}
	fgets(buf, sizeof(buf), fp);
	while (fgets(buf, sizeof(buf), fp))
	{
		if (sscanf(buf, "%15s %lx %lx", iface, &dest, &gw) == 3)
		{
			if (dest == 0)
			{
				gw_addr.s_addr = gw;
				printf("gateway is %s\n", inet_ntoa(gw_addr));
				strncpy(gateway_ip, inet_ntoa(gw_addr), 16);
				fclose(fp);
				return ;
			}
		}
	}
	fprintf(stderr, "Could not find gateway\n");
	fclose(fp);
}

void	check_errors(int argc)
{
	if (getuid() != 0)
	{
		fprintf(stderr, "You must be root to use this program\n");
		exit (1);
	}
	if (argc < 2)
	{
		usage();
		exit (1);
	}
}
