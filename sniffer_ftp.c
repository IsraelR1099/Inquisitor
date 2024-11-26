#include "inquisitor.h"

static void	print_payload(const u_char *payload, int len)
{
	int	i;

	for (i = 0; i < len; i++)
	{
		if (isprint(payload[i]))
			printf("%c", payload[i]);
		else
			printf(".");
	}
	printf("\n");
}

static void	check_ftp_command(const u_char *payload, int len)
{
	const char	*commands[] = {"STOR", "RETR"};
	char		*payload_copy;
	char		*command;
	char		*arg_start;
	char		*arg_end;

	payload_copy = strndup((const char *)payload, len);
	if (payload_copy == NULL)
	{
		fprintf(stderr, "Error: strndup() failed\n");
		return ;
	}
	for (int i = 0; i < len; i++)
		payload_copy[i] = toupper(payload_copy[i]);
	for (int i = 0; i < 2; i++)
	{
		command = strstr(payload_copy, commands[i]);
		if (command)
		{
			//printf(TC_RED "FTP Command detected: %s\n" TC_NRM, commands[i]);
			arg_start = command + strlen(commands[i] + 1);
			arg_end = strchr(arg_start, '\r');
			if (arg_start && arg_end)
			{
				*arg_end = '\0';
				printf(TC_GRN "Filename: %s\n" TC_NRM, arg_start);
			}
			else
				printf("No argument found\n");
		}
	}
	free(payload_copy);
}

static void	process_packet(t_info *info, const u_char *packet, int len)
{
	struct iphdr	*ip;
	int				ip_hdr_len;
	int				tcp_hdr_len;
	int				payload_offset;
	int				payload_len;
	struct tcphdr	*tcp;
	const u_char	*payload;

	ip = (struct iphdr *)(packet + sizeof(struct ethhdr));
	if (ip->protocol == IPPROTO_TCP)
	{
		tcp = (struct tcphdr *)(packet + sizeof(struct ethhdr) + (ip->ihl * 4));
		ip_hdr_len = ip->ihl * 4;
		tcp_hdr_len = tcp->doff * 4;
		payload_offset = sizeof(struct ethhdr) + ip_hdr_len + tcp_hdr_len;
		payload_len = len - payload_offset;
		if (payload_len > 0)
		{
			payload = packet + payload_offset;
			if (verbose)
			{
				printf("Payload (%d bytes):\n", payload_len);
				print_payload(packet + payload_offset, payload_len);
			}
			else
				check_ftp_command(payload, payload_len);
		}
	}
	forward_packet(info, packet, len);
}

static void	process_packet_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	t_info			*info;
	struct ethhdr	*eth;
	struct iphdr	*ip;
	struct tcphdr	*tcp;
	static int	count = 0;

	info = (t_info *)args;
	eth = (struct ethhdr *)packet;
	if (verbose)
	{
			printf("Ethernet: Source MAC: %02x:%02x:%02x:%02x:%02x:%02x | Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
					eth->h_source[0], eth->h_source[1], eth->h_source[2],
					eth->h_source[3], eth->h_source[4], eth->h_source[5],
					eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
					eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
	}
	ip = (struct iphdr *)(packet + sizeof(struct ethhdr));
	if (verbose)
	{
			printf("IP: Source: %s | Destination: %s | Protocol: %d\n",
					inet_ntoa(*(struct in_addr *)&ip->saddr),
					inet_ntoa(*(struct in_addr *)&ip->daddr),
					ip->protocol);
	}
	if (ip->protocol == IPPROTO_TCP)
	{
		tcp = (struct tcphdr *)(packet + sizeof(struct ethhdr) + (ip->ihl * 4));
		if (verbose)
		{
				printf("TCP: Source Port: %d | Destination Port: %d | Flags: 0x%x\n",
						ntohs(tcp->source), ntohs(tcp->dest), tcp->th_flags);
		}
		if (ntohs(tcp->source) == 21 || ntohs(tcp->dest) == 21)
		{
			if (count < 2)
				printf("FTP Command detected\n");
		}
		else if (ntohs(tcp->source) == 20 || ntohs(tcp->dest) == 20)
			printf("FTP Data transfer detected\n");
	}
	else
		printf("Non-TCP packet captured\n");
	count++;
	process_packet(info, packet, header->len);
}

void	*sniff_ftp(void *arg)
{
	char				errbuf[PCAP_ERRBUF_SIZE];
	t_info				*info;
	struct bpf_program	fp;
	char				filter_exp[] = "port 21 or port 20";
	bpf_u_int32			net;
	int					ret;

	info = (t_info *)arg;
	net = 0;
	handle = pcap_open_live(info->dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL)
	{
		fprintf(stderr, "Couldn't open device %s: %s\n", info->dev, errbuf);
		return (NULL);
	}
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1)
	{
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return (NULL);
	}
	if (pcap_setfilter(handle, &fp) == -1)
	{
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return (NULL);
	}
	printf("FTP sniffer started on %s\n", info->dev);
	while (!stop)
	{
		ret = pcap_dispatch(handle, -1, process_packet_callback, (u_char *)info);
		if (ret < 0)
		{
			fprintf(stderr, "Error: pcap_dispatch() failed\n");
			break ;
		}
	}
	printf(TC_RED"FTP sniffer stopped\n" TC_NRM);
	pcap_freecode(&fp);
	pcap_close(handle);
	return (NULL);
}
