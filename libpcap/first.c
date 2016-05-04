#include <stdio.h> 
#include <pcap.h> 

int main() 
{ 
	char *dev, errbuf[PCAP_ERRBUF_SIZE]; 
	dev = pcap_lookupdev(errbuf); 
//上面这个函数返回第一个合适的网络接口的字符串指针，如果出错，则errbuf存放出错信息字符串，errbuf至少应该是PCAP_ERRBUF_SIZE个字节长度的
	printf("Device: %s", dev); 
	return(0);  
}