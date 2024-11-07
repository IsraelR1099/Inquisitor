#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>

static void process_packet(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
  int i;
  int *counter;

  counter = (int *)arg;
  printf("Packet count %d\n", ++(*counter));
  printf("Received packet size %d\n", pkthdr->len);
  printf("Payload:\n");
  for (i = 0; i < (int)pkthdr->len; i++)
  {
    if (isprint(packet[i]))
      printf("%c ", packet[i]);
     else {
      printf(". ");
     }
    if ((i % 16 == 0 && i != 0) || i == (int)pkthdr->len -1)
      printf("\n");
  }
}

int main(void)
{
  int       count;
  pcap_t    *descr;
  pcap_if_t *all_devs;
  char      errbuf[PCAP_ERRBUF_SIZE];
  char      *device;

  memset(errbuf, 0, PCAP_ERRBUF_SIZE);
  if (pcap_findalldevs(&all_devs, errbuf) < 0)
  {
    fprintf(stderr, "Error: pcap_findalldevs error %s\n", errbuf);
    exit (EXIT_FAILURE);
  }
  device = all_devs->name;
  printf("Opening device: %s\n", device);
  if ((descr = pcap_open_live(device, 2048, 0, 512, errbuf)) == NULL)
  {
    fprintf(stderr, "Error: %s\n", errbuf);
    exit (EXIT_FAILURE);
  }
  if (pcap_loop(descr, -1, process_packet, (u_char *)&count) < -1)
  {
    fprintf(stderr, "Error: %s\n", pcap_geterr(descr));
    exit (EXIT_FAILURE);
  }
  return (EXIT_SUCCESS);
}
