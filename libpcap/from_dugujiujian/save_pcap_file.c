#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <time.h>

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
int main(int argc,char **argv)
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i=0;
	pcap_t *adhandle;//定义文件句柄
	char errbuf[PCAP_ERRBUF_SIZE + 1];
	pcap_dumper_t *dumpfile;

	/*检查命令行参数，是否带有文件名*/
	if(argc != 2){
		printf("usage: %s filename", argv[0]);
		return -1;
	}
	
	/* 获得驱动列表 */
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

	/* 跳转到指定的网卡 */
	for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);
	/* Open the adapter */
	if ((adhandle= pcap_open_live(d->name, 65536, 1, 1000, errbuf )) == NULL)
	{
		fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	} 
	
	/*打开文件*/
	dumpfile = pcap_dump_open(adhandle, argv[1]);
	if(dumpfile==NULL){
		fprintf(stderr,"\nError opening output file\n");
		return -1;
	} 
	printf("\nlistening on %s...\n", d->name);
	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);
	/* start the capture */
	pcap_loop(adhandle, 0, packet_handler, NULL);
	return 0;
}

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	printf("-----------");
	pcap_dump(param,header,pkt_data);
}