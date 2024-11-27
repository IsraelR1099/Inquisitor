#ifndef INQUISITOR_H
# define INQUISITOR_H

# include <stdio.h>
# include <string.h>
# include <stdlib.h>
# include <unistd.h>
# include <pcap.h>
# include <signal.h>
# include <netinet/if_ether.h>
# include <sys/socket.h>
# include <netpacket/packet.h>
# include <net/ethernet.h>
# include <net/if.h>
# include <netinet/ip.h>
# include <netinet/tcp.h>
# include <netinet/udp.h>
# include <netinet/ip_icmp.h>
# include <stdbool.h>
# include <errno.h>
# include <pthread.h>
# include <ctype.h>

# define ARP_REQUEST 1
# define ARP_REPLY 2
# define POISON_DURATION 300
# define POISON_INTERVAL 2
# define MAC_ADDR_LEN 6
# define IP_ADDR_LEN 4
# define IP4LEN 4
# define PKTLEN sizeof(struct ether_header) + sizeof(struct ether_arp)

# define TC_NRM  "\x1B[0m"
# define TC_RED  "\x1B[31m"
# define TC_GRN  "\x1B[32m"
# define TC_YEL  "\x1B[33m"
# define TC_BLU  "\x1B[34m"

extern bool						verbose;
extern int						sock;
extern volatile sig_atomic_t	stop;
extern pcap_t					*handle;

typedef struct arphdr_s
{
    u_int16_t   htype;  //Hardware type
    u_int16_t   ptype;  //Protocol type
    u_int16_t   oper;   //Operation code
    u_char      hlen;   //Hardware address length
    u_char      plen;   //Protocol address length
    u_char      sha[6]; //Sender hardware address
    u_char      spa[4]; //Sender IP address
    u_char      tha[6]; //Target hardware address
    u_char      tpa[4]; //Target IP address
}   arphdr_t;

typedef struct	s_info
{
	char		*dev;
	char		*ip_src;
	char		*ip_target;
	char		*mac_src;
	char		*mac_target;
	char		gateway_ip[16];
	char		gateway_mac[18];
	pcap_t		*handle;
}	t_info;

typedef struct s_pseudo_hdr
{
	u_int32_t	src;
	u_int32_t	dst;
	u_int8_t	zero;
	u_int8_t	protocol;
	u_int16_t	len;
}	t_pseudo_hdr;

// Utils
void	usage(void);
void	get_gateway(char *gateway_ip);
void	check_errors(int argc);
void	check_syntax(t_info *info);
bool	is_duplicate(const u_char *payload, int len);
int		get_gateway_mac(char *target_ip, char *mac);

// Signals
void	sigint_handler(int signum);

// Setting headers
void	set_hdrs(struct ether_header *eth, struct ether_arp *arp, u_char *source_mac, char *ip_target);
void	spoof_gateway(struct ether_header *eth, struct ether_arp *arp, u_char *source_mac, char *ip_target);
void	*sniff_ftp(void *arg);

// Forwarding packets
void	forward_packet(t_info *info, const u_char *packet, int len);
#endif
