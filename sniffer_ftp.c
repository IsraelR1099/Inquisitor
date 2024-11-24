#include "inquisitor.h"

static void	forward_packet(t_info *info, const u_char *packet, int len)
{
	int					sockfd;
	struct sockaddr_in	dest_info;

	sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (sockfd < 0)
	{
		perror("socket");
		return ;
	}
	dest_info.sin_family = AF_INET;
	dest_info.sin_port = htons(0);
	dest_info.sin_addr.s_addr = inet_addr(info->ip_target);
	printf("Forwarding packet to %s\n", info->ip_target);
	if (sendto(sockfd, packet, len, 0, (struct sockaddr *)&dest_info, sizeof(dest_info)) < 0)
	{
		perror("sendto");
		return ;
	}
	close(sockfd);
}

static void	process_packet(t_info *info, const u_char *packet, int len)
{
	forward_packet(info, packet, len);
}

static void	process_packet_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	t_info	*info;

	info = (t_info *)args;
	printf("Packet captured\n");
	if (info->handle == NULL)
	{
		printf("Handle is NULL\n");
	}
	if (header->len > 0)
	{
		process_packet(info, packet, header->len);
	}
	if (stop == 1)
	{
		print("Breaking pcap_loop...\n");
		pcap_breakloop((pcap_t *)info->handle);
	}
}

void	*sniff_ftp(void *arg)
{
	char				errbuf[PCAP_ERRBUF_SIZE];
	pcap_t				*handle;
//	struct pcap_pkthdr	header;
//	const u_char		*packet;
	t_info				*info;
	struct bpf_program	fp;
	char				filter_exp[] = "port 21 or port 20";
	bpf_u_int32			net;

	info = (t_info *)arg;
	net = 0;
	handle = pcap_open_live(info->dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL)
	{
		fprintf(stderr, "Couldn't open device %s: %s\n", info->dev, errbuf);
		return (NULL);
	}
	info->handle = handle;
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
	pcap_loop(handle, -1, process_packet_callback, (u_char *)info);
	printf("FTP sniffer stopped\n");
	pcap_freecode(&fp);
	pcap_close(handle);
	return (NULL);
}
