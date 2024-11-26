#include "inquisitor.h"

static uint16_t	checksum(void *data, int len)
{
	uint32_t	sum;
	uint16_t	*ptr;

	sum = 0;
	ptr = (uint16_t *)data;
	while (len > 1)
	{
		sum += *ptr++;
		if (sum & 0x80000000)
			sum = (sum & 0xFFFF) + (sum >> 16);
		len -= 2;
	}
	if (len)
		sum += *(uint8_t *)ptr;
	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);
	return (~sum);
}

void	forward_packet(t_info *info, const u_char *packet, int len)
{
	int					sockfd;
	struct sockaddr_in	dest_info;
	int					on;
	struct iphdr *ip = (struct iphdr *)(packet + sizeof(struct ethhdr));
	struct tcphdr		*tcp;
	t_pseudo_hdr		pseudo_hdr;
	uint8_t				pseudo_packet[sizeof(t_pseudo_hdr) + len - sizeof(struct ethhdr) - (ip->ihl * 4)];

	tcp = (struct tcphdr *)(packet + sizeof(struct ethhdr) + (ip->ihl * 4));
	sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (sockfd < 0)
	{
		perror("socket");
		return ;
	}
	on = 1;
	if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)
	{
		perror("setsockopt");
		close(sockfd);
		return ;
	}
	ip->daddr = inet_addr(info->ip_target);
	ip->check = 0;
	ip->check = checksum(ip, ip->ihl * 4);
	tcp->check = 0;
	pseudo_hdr.src = ip->saddr;
	pseudo_hdr.dst = ip->daddr;
	pseudo_hdr.zero = 0;
	pseudo_hdr.protocol = IPPROTO_TCP;
	pseudo_hdr.len = htons(len - sizeof(struct ethhdr) - (ip->ihl * 4));

	memcpy(pseudo_packet, &pseudo_hdr, sizeof(t_pseudo_hdr));
	memcpy(pseudo_packet + sizeof(t_pseudo_hdr), tcp, len - sizeof(struct ethhdr) - (ip->ihl * 4));

	tcp->check = checksum(pseudo_packet, sizeof(t_pseudo_hdr));

	dest_info.sin_family = AF_INET;
	dest_info.sin_port = htons(0);
	dest_info.sin_addr.s_addr = ip->daddr;

	//printf("Forwarding packet to %s\n", info->ip_target);
	if (sendto(sockfd, packet + sizeof(struct ethhdr), len - sizeof(struct ethhdr), 0, (struct sockaddr *)&dest_info, sizeof(dest_info)) < 0)
		perror("sendto");
	close(sockfd);
}

