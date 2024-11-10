#ifndef INQUISITOR_H
# define INQUISITOR_H

# include <stdio.h>
# include <string.h>
# include <stdlib.h>
# include <unistd.h>
# include <pcap.h>
# include <signal.h>
# include <netinet/if_ether.h>
# include <netinet/ip.h>
# include <netinet/tcp.h>
# include <netinet/udp.h>
# include <netinet/ip_icmp.h>

# define ARP_REQUEST 1
# define ARP_REPLY 2

pcap_t  *handle;
int     linkhdrlen;
int     packets;

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

#endif
