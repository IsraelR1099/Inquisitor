#include <pcap.h>
#include <stdlib.h>
#include <string.h>

#define ARP_REQUEST 1
#define ARP_REPLY 2
#define MAXBYTES2CAPTURE 2048

typedef struct arphdr
{
  u_int16_t htype; //Hardware type 
  u_int16_t ptype; //Protocol type
  u_char    hlen; //Hardware address length
  u_char    plen; //Protocol address length
  u_int16_t oper; //Operation code
  u_char    sha[6]; //Sender hardware address
  u_char    spa[4]; //Sender IP address
  u_char    tha[6]; //Target hardware address
  u_char    tpa[4]; //Target IP address
} arphdr_t;

int main(void)
{
  int                 i;
  bpf_u_int32         netaddr;
  bpf_u_int32         mask;
  struct bpf_program  filter;
  char                errbuf[PCAP_ERRBUF_SIZE];
  pcap_t              *descr;
  struct pcap_pkthdr  pkthdr;
  const unsigned char *packet;
  arphdr_t            *arpheader;
  pcap_if_t           *all_devs;
  char                *dev;

  i = 0;
  netaddr = 0;
  mask = 0;
  descr = NULL;
  packet = NULL;
  arpheader = NULL;
  memset(errbuf, 0, PCAP_ERRBUF_SIZE);
  if (pcap_findalldevs(&all_devs, errbuf) < 0)
  {
    fprintf(stderr, "Error pcap_findalldevs: %s\n", errbuf);
    exit (EXIT_FAILURE);
  }
  dev = all_devs->name;
  printf("Device: %s\n", dev);
  descr = pcap_open_live(dev, MAXBYTES2CAPTURE, 0, 512, errbuf);
  pcap_lookupnet(dev, &netaddr, &mask, errbuf);
  pcap_compile(descr, &filter, "arp", 1, mask);
  pcap_setfilter(descr, &filter);
  while (1)
  {
    packet = pcap_next(descr, &pkthdr);
    arpheader = (struct arphdr *)(packet + 14);
    printf("\n\nReceived Packet size: %d bytes\n", pkthdr.len);
    printf("Hardware type: %s\n", (ntohs(arpheader->htype) == 1) ? "Ethernet" : "Unknown");
    printf("Protocol type: %s\n", (ntohs(arpheader->ptype) == 0x800) ? "IPv4" : "Unknown");
    printf("Operation: %s\n", (ntohs(arpheader->oper) == ARP_REQUEST) ? "ARP Request" : "ARP Reply");
    if (ntohs(arpheader->htype) == 1 &&
        ntohs(arpheader->ptype) == 0x800)
    {
      printf("Sender MAC:");
      for (i = 0; i < 6; i++)
        printf("%02X:", arpheader->sha[i]);
      printf("Sender IP:");
      for(i = 0; i < 4; i++)
        printf("%d.", arpheader->spa[i]);
      printf("\nTarget MAC:");
      for (i = 0; i < 6; i++)
        printf("%02X:", arpheader->tha[i]);
      printf("\nTarget IP:");
      for (i = 0; i < 4; i++)
        printf("%d.", arpheader->tpa[i]);
      printf("\n");
    }
  }
  return (0);
}
