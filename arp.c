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
/*
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
*/
static void	send_icmp(char *ip_target)
{
	int					sock;
	char				packet[256];
	struct icmp 	*icmp;
	struct sockaddr_in	target;

	icmp = (struct icmp *)packet;
	sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	icmp->icmp_type = ICMP_ECHO;
	icmp->icmp_code = 0;
	icmp->icmp_cksum = 0;
	icmp->icmp_id = getpid();
	icmp->icmp_seq = 1;

	target.sin_family = AF_INET;
	target.sin_addr.s_addr = inet_addr(ip_target);
	while (1)
	{
		sendto(sock, packet, sizeof(packet), 0, (struct sockaddr *)&target, sizeof(target));
	}
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
	send_icmp(ip_target);
	//set_arp_spoof(dev, ip_src, mac_src, ip_target, mac_target, verbose);
//	(void)errbuf;
	(void)verbose;
	(void)mac_target;
	(void)ip_src;
	(void)mac_src;
	return (0);
}
