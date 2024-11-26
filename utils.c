/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   utils.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: irifarac <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/11/22 11:54:49 by irifarac          #+#    #+#             */
/*   Updated: 2024/11/26 20:27:54 by israel           ###   ########.fr       */
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

void	check_syntax(t_info *info)
{
	struct ether_arp	*arp;
	char				buffer[42] = {0};
	u_char				source_mac[MAC_ADDR_LEN] = {0};
	u_char				dest_mac[MAC_ADDR_LEN] = {0};

	arp = (struct ether_arp *)(buffer + sizeof(struct ether_header));
	if (inet_pton(AF_INET, info->ip_src, &arp->arp_spa) != 1)
	{
		fprintf(stderr, "Invalid source IP address\n");
		exit(1);
	}
	if (inet_pton(AF_INET, info->ip_target, &arp->arp_tpa) != 1)
	{
		fprintf(stderr, "Invalid destination IP address\n");
		exit(1);
	}
	if (sscanf(info->mac_src, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
		&source_mac[0], &source_mac[1], &source_mac[2],
		&source_mac[3], &source_mac[4], &source_mac[5]) != 6)
	{
		fprintf(stderr, "Invalid source MAC address\n");
		exit(1);
	}
	if (sscanf(info->mac_target, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
		&dest_mac[0], &dest_mac[1], &dest_mac[2],
		&dest_mac[3], &dest_mac[4], &dest_mac[5]) != 6)
	{
		fprintf(stderr, "Invalid destination MAC address\n");
		exit(1);
	}
}
