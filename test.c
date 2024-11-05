#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <pcap.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>

int	main(int argc, char **argv)
{
  char	              *dev;
  char                errbuf[PCAP_ERRBUF_SIZE];
  pcap_t              *handle;
  pcap_if_t           *all_devs;
  const unsigned char *packet;
  struct pcap_pkthdr  pk_header;
  struct ether_header *eptr;
  unsigned char       *ptr;
  int                 i;

	if (argc < 2)
	{
		fprintf(stderr, "Wrong number of arguments");
		exit (1);
	}
  if (pcap_findalldevs(&all_devs, errbuf) < 0)
  {
    fprintf(stderr, "Error: pcap_findalldevs error %s\n", errbuf);
    exit (EXIT_FAILURE);
  }
  dev = all_devs->name;
  printf("Device: %s\n", dev);
  handle = pcap_open_live(dev, BUFSIZ, 0, 10000000, errbuf);
  if (handle == NULL)
  {
    fprintf(stderr, "Error: pcap_open_live error %s\n", errbuf);
    exit (EXIT_FAILURE);
  }
  packet = pcap_next(handle, &pk_header);
  if (packet == NULL)
  {
    fprintf(stderr, "No packet found\n");
    exit (EXIT_FAILURE);
  }
  printf("Grabbed packet of length %d\n", pk_header.len);
  printf("Received at: %s\n", ctime((const time_t *)&pk_header.ts.tv_sec));
  printf("Ethernet addess length is %d\n", ETHER_HDR_LEN);
  eptr = (struct ether_header *)packet;
  if (ntohs(eptr->ether_type) == ETHERTYPE_IP)
  {
    printf("Ethernet type hex:%x dec:%d is an IP packet\n",
           ntohs(eptr->ether_type),
           ntohs(eptr->ether_type));
  }
  else if (ntohs(eptr->ether_type) == ETHERTYPE_ARP)
  {
    printf("Ethernet type hex:%x dec:%d is an ARP packet\n",
           ntohs(eptr->ether_type),
           ntohs(eptr->ether_type));
  }
  else {
    printf("Ethernet type %x not IP type\n", ntohs(eptr->ether_type));
  }
  ptr = eptr->ether_dhost;
  i = ETHER_ADDR_LEN;
  printf("Destination address...:");
  do {
    printf("%s%x", (i == ETHER_ADDR_LEN) ? " " : ":", *ptr++);
  } while (--i > 0);
  printf("\n");
  printf("Source address...:");
  ptr = eptr->ether_shost;
  i = ETHER_ADDR_LEN;
  do {
    printf("%s%x", (i == ETHER_ADDR_LEN) ? " " : ":", *ptr++);
  } while (--i > 0);
  printf("Success\n");
  (void)argv;
  return (EXIT_SUCCESS);
}
