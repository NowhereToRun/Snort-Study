#include <stdio.h> 
#include <pcap.h> 

int main() 
{ 
	char *dev, errbuf[PCAP_ERRBUF_SIZE]; 
	dev = pcap_lookupdev(errbuf); 
//��������������ص�һ�����ʵ�����ӿڵ��ַ���ָ�룬���������errbuf��ų�����Ϣ�ַ�����errbuf����Ӧ����PCAP_ERRBUF_SIZE���ֽڳ��ȵ�
	printf("Device: %s", dev); 
	return(0);  
}