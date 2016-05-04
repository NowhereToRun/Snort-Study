#include "pcap.h"
#include "stdlib.h"
int main()
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int i=0;
	char errbuf[PCAP_ERRBUF_SIZE];
	
	if (pcap_findalldevs(&alldevs,errbuf) == -1){
		printf("Error in pcap_findalldevs:%s\n",errbuf);
		exit(1);
	}
	/*显示列表的相应字段的内容*/
	for (d=alldevs;d;d=d->next){
		printf("%d.%s",++i,d->name);
		if(d->description)
			printf("(%s)\n",d->description);
		else
			printf("(No description available)\n");
	}
	if(i==0){
		printf("\nNo interfaces found!Make sure LibPcap is installed.\n");
		return;
	}
	/*We don't need any more the device list.Free it*/
	pcap_freealldevs(alldevs);
}