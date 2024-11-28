#include "inquisitor.h"

void	restore_arp(t_info *info)
{
	char				buffer[42] = {0};
	struct ether_header	*eth;
	struct ether_arp	*arp;
	struct sockaddr_ll	device;
	u_char				source_mac[MAC_ADDR_LEN];
	int					sockfd;
	int					interval;

	eth = (struct ether_header *)buffer;
	arp = (struct ether_arp *)(buffer + sizeof(struct ether_header));
	interval = 0;
	sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
	if (sockfd < 0)
	{
		perror("socket");
		exit(EXIT_FAILURE);
	}
	if (sscanf(info->gateway_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
		&source_mac[0], &source_mac[1], &source_mac[2],
		&source_mac[3], &source_mac[4], &source_mac[5]) != MAC_ADDR_LEN)
	{
		fprintf(stderr, "Invalid MAC address\n");
		exit(EXIT_FAILURE);
	}
	memset(&device, 0, sizeof(device));
	device.sll_family = AF_PACKET;
	device.sll_ifindex = if_nametoindex(info->dev);
	if (device.sll_ifindex == 0)
	{
		perror("if_nametoindex");
		exit(EXIT_FAILURE);
	}
	device.sll_halen = ETH_ALEN;
	while (interval < 15)
	{
		set_hdrs(eth, arp, source_mac, info->ip_target);
		printf("Restoring ARP cache of %s\n", info->ip_target);
		if (sendto(sockfd, buffer, sizeof(buffer), 0,
			(struct sockaddr *)&device, sizeof(device)) < 0)
		{
			perror("sendto");
			exit(EXIT_FAILURE);
		}
		sleep(2);
		interval++;
	}
	close(sockfd);
}
