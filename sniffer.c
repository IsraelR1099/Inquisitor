#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap.h>
#include <signal.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

pcap_t  *handle;
int     linkhdrlen;
int     packets;

static void    stop_process(int signo)
{
    struct pcap_stat    stats;

    if (pcap_stats(handle, &stats) >= 0)
    {
        printf("\n%d packets captured\n", packets);
        printf("%d packets received\n", stats.ps_recv);
        printf("%d packets dropped\n", stats.ps_drop);
    }
    pcap_close(handle);
    (void)signo;
    exit (0);
}

static pcap_t   *create_pcap_handle(char *device, char *filter)
{
    char                errbuf[PCAP_ERRBUF_SIZE];
    pcap_t              *handle;
    pcap_if_t           *devices;
    struct bpf_program  bpf;
    bpf_u_int32         netmask;
    bpf_u_int32         srcip;

    if (!*device)
    {
        if (pcap_findalldevs(&devices, errbuf))
        {
            fprintf(stderr, "Error: pcap_findalldevs(): %s\n", errbuf);
            return (NULL);
        }
        strcpy(device, devices[0].name);
    }
    if (pcap_lookupnet(device, &srcip, &netmask, errbuf) == PCAP_ERROR)
    {
        fprintf(stderr, "Error: pcap_lookupnet(): %s\n", errbuf);
        return (NULL);
    }
    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "Error: pcap_open_live(): %s\n", errbuf);
        return (NULL);
    }
    if (pcap_compile(handle, &bpf, filter, 0, netmask) == PCAP_ERROR)
    {
        fprintf(stderr, "Error: pcap_compile(): %s\n", pcap_geterr(handle));
        return (NULL);
    }
    if (pcap_setfilter(handle, &bpf) == PCAP_ERROR)
    {
        fprintf(stderr, "Error: pcap_setfilter(): %s\n", pcap_geterr(handle));
        return (NULL);
    }
    return (handle);
}

static void    get_link_hdr_len(pcap_t *handle)
{
    int linktype;

    linktype = pcap_datalink(handle);
    if (linktype == PCAP_ERROR)
    {
        fprintf(stderr, "Error: pcap_datalink(): %s\n", pcap_geterr(handle));
        return ;
    }
    switch(linktype)
    {
        case DLT_NULL:
            linkhdrlen = 4;
            break ;
        case DLT_EN10MB:
            linkhdrlen = 14;
            break ;
        case DLT_SLIP:
            linkhdrlen = 24;
            break ;
        case DLT_PPP:
            linkhdrlen = 24;
            break ;
        default:
            printf("Unsupported datalink (%d)\n", linktype);
            linkhdrlen = 0;
    }
}

static void callback(u_char *user, const struct pcap_pkthdr *packethdr, const u_char *packetptr)
{
    struct ip       *iphdr;
    struct icmp     *icmphdr;
    struct tcphdr   *tcphdr;
    struct udphdr   *udphdr;
    char            iphdr_info[256] = {0};
    char            src_ip[256] = {0};
    char            dst_ip[256] = {0};

    packethdr += linkhdrlen;
    iphdr = (struct ip *)packetptr;
    strcpy(src_ip, inet_ntoa(iphdr->ip_src));
    strcpy(dst_ip, inet_ntoa(iphdr->ip_dst));
    sprintf(iphdr_info, "ID:%d TOS:0x%x, TTL:%d IpLen:%d DgLen:%d",
            ntohs(iphdr->ip_id), iphdr->ip_tos, iphdr->ip_ttl,
            4 * iphdr->ip_hl, ntohs(iphdr->ip_len));
    packetptr += 4 * iphdr->ip_hl;
    printf("iphdr protocol %d\n", iphdr->ip_p);
    printf("IPPROTO ICMP is %d\n", IPPROTO_ICMP);
    switch(iphdr->ip_p)
    {
        case IPPROTO_TCP:
            tcphdr = (struct tcphdr *)packetptr;
            printf("TCP %s:%d -> %s:%d\n", src_ip, ntohs(tcphdr->th_sport),
                   dst_ip, ntohs(tcphdr->th_dport));
            printf("%s\n", iphdr_info);
            printf("%c%c%c%c%c%c Seq: 0x%x Ack: 0x%x Win: 0x%x TcpLen: %d\n",
                   (tcphdr->th_flags & TH_URG ? 'U' : '*'),
                   (tcphdr->th_flags & TH_ACK ? 'A' : '*'),
                   (tcphdr->th_flags & TH_PUSH ? 'P' : '*'),
                   (tcphdr->th_flags & TH_RST ? 'R' : '*'),
                   (tcphdr->th_flags & TH_SYN ? 'S' : '*'),
                   (tcphdr->th_flags & TH_SYN ? 'F' : '*'),
                   ntohl(tcphdr->th_seq), ntohl(tcphdr->th_ack),
                   ntohs(tcphdr->th_win), 4 * tcphdr->th_off);
            printf("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n\n");
            packets += 1;
            break ;
        case IPPROTO_UDP:
            udphdr = (struct udphdr *)packetptr;
            printf("UDP %s:%d -> %s:%d\n", src_ip, ntohs(udphdr->uh_sport),
                   dst_ip, ntohs(udphdr->uh_dport));
            printf("%s\n", iphdr_info);
            printf("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n\n");
            packets += 1;
            break ;
        case IPPROTO_ICMP:
            icmphdr = (struct icmp *)packetptr;
            printf("ICMP %s -> %s\n", src_ip, dst_ip);
            printf("%s\n", iphdr_info);
            printf("Type:%d Code:%d ID:%d Seq:%d\n", icmphdr->icmp_type,
                   icmphdr->icmp_code, ntohs(icmphdr->icmp_hun.ih_idseq.icd_id),
                   ntohs(icmphdr->icmp_hun.ih_idseq.icd_seq));
            printf("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n\n");
            packets += 1;
            break ;
        default:
            printf("Unknown ");
    }
    (void)user;
}

int main(int argc, char *argv[])
{
    char    device[256];
    char    filter[256];
    int     count;
    int     opt;

    count = 0;
    memset(device, 0, sizeof(device));
    memset(filter, 0, sizeof(filter));
    while ((opt = getopt(argc, argv, "hn:")) != -1)
    {
        switch(opt)
        {
            case 'h':
                printf("Usage: %s [-h] [-n count] [BPF Expression]\n", argv[0]);
                exit (0);
                break ;
            case 'n':
                count = atoi(optarg);
                if (count < 0)
                {
                    printf("Not valid count number: %d", count);
                    exit (1);
                }
                break ;
        }
    }
    for (int i = optind; i < argc; i++)
    {
        strcat(filter, argv[i]);
        strcat(filter, " ");
    }
    printf("filter is '%s'\n", filter);
    signal(SIGINT, stop_process);
    handle = create_pcap_handle(device, filter);
    if (handle == NULL)
        return (-1);
    printf("filtering by: %s on device %s\n", filter, device);
    get_link_hdr_len(handle);
    printf("linkhdrlen es %d\n", linkhdrlen);
    if (linkhdrlen == 0)
        return (-1);
    if (pcap_loop(handle, count, callback, (u_char *)NULL) < 0)
    {
        fprintf(stderr, "Error: pcap_loop(): %s\n", pcap_geterr(handle));
        return (-1);
    }
    stop_process(0);
    return (0);
}
