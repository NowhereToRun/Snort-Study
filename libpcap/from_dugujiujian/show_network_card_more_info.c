#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/socket.h>

#define MAXBYTES2CAPTURE 2048

void processPacket(u_char *arg, const struct pcap_pkthdr* pkthdr, const u_char * packet)
{
	int i=0, *counter = (int *)arg; 
	printf("Packet Count: %d\n", ++(*counter));
	printf("Received Packet Size: %d\n", pkthdr->len); 
	printf("Payload:\n");
	for (i=0; i<pkthdr->len; i++){
		if ( isprint(packet[i]) ) 
			printf("%c ", packet[i]);
		else
			printf(". ");

		if( (i%16 == 0 && i!=0) || i==pkthdr->len-1 ) 
			printf("\n");
	}
	return;
}

#define IPTOSBUFFERS 12
char *iptos(u_long in)
{
	static char output[IPTOSBUFFERS][3*4+3+1];
	static short which;
	u_char *p;
	
	p = (u_char *)&in;
	which = (which + 1 == IPTOSBUFFERS ? 0 : which +1);
	sprintf(output[which],"%d.%d.%d.%d",p[0],p[1],p[2],p[3]);
	return output[which];
}

void ifprint(pcap_if_t *d)
{
	pcap_addr_t *a;
	
	/*Name*/
	printf("%s\n",d->name);
	/*Description*/
	if(d->description)
		printf("\tDescription:%s\n",d->description);
	/*Loopback Address*/
	//printf("\tLoopback:%s\n",(d->flag & PCAP_IF_LOOPBACK)?"yes":"no");
	/*IP addresses*/
	for(a=d->addresses;a;a=a->next){
		printf("\tAddress Family:#%d\n",a->addr->sa_family);
		switch(a->addr->sa_family){
			case AF_INET:
				printf("\tAddress Family Name:AF_INET\n");
				if (a->addr)
					printf("\tAddress: %s\n",iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr));
				if (a->netmask)
					printf("\tNetmask: %s\n",iptos(((struct sockaddr_in *)a->netmask)->sin_addr.s_addr));
				if (a->broadaddr)
					printf("\tBroadcast Address: %s\n",iptos(((struct sockaddr_in *)a->broadaddr)->sin_addr.s_addr));
				if (a->dstaddr)
					printf("\tDestination Address: %s\n",iptos(((struct sockaddr_in *)a->dstaddr)->sin_addr.s_addr));
				break;
			default:
				printf("\tAddress Family Name:Unknown\n");
				break;
		}
	}
	printf("\n");
}

int main(){
	pcap_if_t *alldevs;
	pcap_if_t *d;
	char errbuf[PCAP_ERRBUF_SIZE+1];
	if (pcap_findalldevs(&alldevs,errbuf) == -1){
		printf("Error in pcap_findalldevs:%s\n",errbuf);
		exit(1);
	}
	/*循环调用ifprint()来显示pcap_if结构的信息*/
	for (d=alldevs;d;d=d->next){
		ifprint(d);
	}
	return 1;
}

