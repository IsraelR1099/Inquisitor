#include "inquisitor.h"

void	*sniff_ftp(void *arg)
{
	char				errbuf[PCAP_ERRBUF_SIZE];
	pcap_t				*handle;
	struct pcap_pkthdr	header;
	const u_char		*packet;
	t_info				*info;
	struct bpf_program	fp;
	char				filter_exp[] = "port 21 or port 20";
	bpf_u_int32			net;

	info = (t_info *)arg;
	net = 0;
	handle = pcap_open_live(info->dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL)
	{
		fprintf(stderr, "Couldn't open device %s: %s\n", info->dev, errbuf);
		return (NULL);
	}
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1)
	{
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return (NULL);
	}
	if (pcap_setfilter(handle, &fp) == -1)
	{
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return (NULL);
	}
	printf("FTP sniffer started on %s\n", info->dev);
	while (!stop)
	{
		packet = pcap_next(handle, &header);
		if (packet == NULL)
			continue;
		//analyze_ftp(packet, header.len);
		printf("Captured a packer with length: %d\n", header.len);
	}
	printf("FTP sniffer stopped\n");
	pcap_close(handle);
	return (NULL);
}
