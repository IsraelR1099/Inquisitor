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

void    stop_process(int signo)
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

int main(int argc, char *argv[])
{
    char    device[256];
    char    filter[256];
    int     count;
    int     opt;

    count = 0;
    memset(device, 0, sizeof(device));
    memset(filter, 0, sizeof(filter));
    while ((opt = getopt(argc, argv, "-hn:")) != -1)
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
    signal(SIGINT, stop_process);
    handle = create_pcap_handle(device, filter);
    if (handle == NULL)
        return (-1);
    return (0);
}
