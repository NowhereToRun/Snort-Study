#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <time.h>
/* 4 BIT IP */
typedef struct ip_address{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

/* IPv4 头的定义*/
typedef struct ip_header{
	u_char ver_ihl; // 4 bit版本信息 + 4 bits的头长
	u_char tos; // TOS类型
	u_short tlen; //总长度
	u_short identification; // Identification
	u_short flags_fo; // Flags (3 bits) + Fragment offset (13 bits)
	u_char ttl; //生存期
	u_char proto; //后面的协议信息
	u_short crc; //校验和
	ip_address saddr; // 源IP
	ip_address daddr; // 目的IP
	u_int op_pad; // Option + Padding
}ip_header;

/* UDP header*/
typedef struct udp_header{
	u_short sport; // Source port
	u_short dport; // Destination port
	u_short len; // Datagram length
	u_short crc; // Checksum
}udp_header;

/* 定义处理包的函数*/
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

int main()
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i=0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE + 1];
	u_int netmask;
	//char packet_filter[] = "ip and udp";
	struct bpf_program fcode;
	/* Retrieve the device list */
	
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		printf("Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	} 
	/* Print the list */

	for(d=alldevs; d; d=d->next)
	{
		printf("%d. %s", ++i, d->name);
	if (d->description)
		printf(" (%s)\n", d->description);
	else
		printf(" (No description available)\n");
	} 
	if(i==0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	} 
	printf("Enter the interface number (1-%d):",i);
	scanf("%d", &inum);
	if(inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		pcap_freealldevs(alldevs);
		return -1;
	} 

	/* Jump to the selected adapter */
	for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);
	/* Open the adapter */

	if ((adhandle= pcap_open_live(d->name, 65536, 1, 1000, errbuf )) == NULL)
	{
		fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	} 
	/* Check the link layer. We support only Ethernet for simplicity. */
	if(pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr,"\nThis program works only on Ethernet networks.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	} 

	if(pcap_compile(adhandle, &fcode, "ip and udp", 1, netmask) <0 )
	{
		fprintf(stderr,"\nUnable to compile the packet filter. Check the syntax.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	} 
	//set the filter
	if(pcap_setfilter(adhandle, &fcode)<0)
	{
		fprintf(stderr,"\nError setting the filter.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	} 
	printf("\nlistening on %s...\n", d->name);
	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);
	/* start the capture */
	pcap_loop(adhandle, 0, packet_handler, NULL);
	return 0;
}
/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	struct tm *ltime;
	char timestr[16];
	ip_header *ih;
	udp_header *uh;
	u_int ip_len;
	u_short sport,dport;

	/* convert the timestamp to readable format */
	ltime=localtime(&header->ts.tv_sec);
	strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);
	/* print timestamp and length of the packet */
	printf("%s.%.6d len:%d ", timestr, header->ts.tv_usec, header->len);
	/* 找到IP头的位置 */
	ih = (ip_header *) (pkt_data + 14); //14为以太头的长度
	/* 找到UDP的位置 */
	ip_len = (ih->ver_ihl & 0xf) * 4;
	uh = (udp_header *) ((u_char*)ih + ip_len);
	/* 将端口信息由网络型转为主机顺序*/
	sport = ntohs( uh->sport );
	dport = ntohs( uh->dport );
	/* print ip addresses and udp ports */
	printf("%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d\n",ih->saddr.byte1,ih->saddr.byte2,ih->saddr.byte3,ih->saddr.byte4,sport,ih->daddr.byte1,ih->daddr.byte2,ih->daddr.byte3,ih->daddr.byte4,dport);
}