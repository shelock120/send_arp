#include <pcap.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <cstring>
#include<dirent.h>
#include<cstdlib>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include "libnet-headers.h"

void send(pcap_t *handle,u_char * packet,libnet_eth_arp_hdr *etharp_hdr,libnet_eth_arp_hdr *recv_etharp_hdr, char mode, u_int8_t* mac_addr, u_int8_t* v_mac_addr, u_int8_t * local_ip, u_int8_t* snd_ip, u_int8_t* trgt_ip)
{

  u_int8_t BROAD[6]={0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  u_int8_t NONE[6]={0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  char m = mode;


  if(m == 'q')

  {
  	memcpy(etharp_hdr -> ether_dhost, BROAD, sizeof(BROAD));
    memcpy(etharp_hdr -> ether_shost, mac_addr, sizeof(mac_addr));
    etharp_hdr -> ether_type = ntohs(ETHERTYPE_ARP);
    etharp_hdr -> ar_hrd = ntohs(ARPHRD_ETHER);
    etharp_hdr -> ar_pro = ntohs(ETHERTYPE_IP);
    etharp_hdr -> ar_hln = ETHER_ADDR_LEN;
    etharp_hdr -> ar_pln = IP_ADDR_LEN;
    etharp_hdr -> ar_op = ntohs(ARPOP_REQUEST);
    memcpy(etharp_hdr -> ar_snd_mac, mac_addr, sizeof(mac_addr));
    memcpy(etharp_hdr -> ar_snd_ip, local_ip, sizeof(local_ip));
    memcpy(etharp_hdr -> ar_trgt_mac, NONE, sizeof(NONE));
    memcpy(etharp_hdr -> ar_trgt_ip, snd_ip, sizeof(snd_ip));
	
    
  memcpy(packet,(const u_char*)etharp_hdr,sizeof(libnet_eth_arp_hdr));
	}

  else if(m == 'p')
  {
  memcpy(recv_etharp_hdr -> ether_dhost, v_mac_addr, sizeof(v_mac_addr));
  memcpy(recv_etharp_hdr -> ether_shost, mac_addr, sizeof(mac_addr));
  recv_etharp_hdr -> ether_type = ntohs(ETHERTYPE_ARP);
  recv_etharp_hdr -> ar_hrd = ntohs(ARPHRD_ETHER);
  recv_etharp_hdr -> ar_pro = ntohs(ETHERTYPE_IP);
  recv_etharp_hdr -> ar_hln = ETHER_ADDR_LEN;
  recv_etharp_hdr -> ar_pln = IP_ADDR_LEN;
  recv_etharp_hdr -> ar_op = ntohs(ARPOP_REQUEST);
  memcpy(recv_etharp_hdr -> ar_snd_mac, mac_addr, sizeof(mac_addr));
  memcpy(recv_etharp_hdr -> ar_snd_ip, trgt_ip, sizeof(trgt_ip));
  memcpy(recv_etharp_hdr -> ar_trgt_mac, v_mac_addr, sizeof(v_mac_addr));
  memcpy(recv_etharp_hdr -> ar_trgt_ip, snd_ip, sizeof(snd_ip));

  memcpy(packet,(const u_char*)recv_etharp_hdr,sizeof(libnet_eth_arp_hdr));
}

  
  for(int i=0; i < sizeof(libnet_eth_arp_hdr); i++)
  {
  	printf("%02x ", packet[i]);
		if((i & 0x0f) == 0x0f)
        printf("\n");
	
  }
  printf("\n");

  int result = pcap_sendpacket(handle, packet, sizeof(libnet_eth_arp_hdr));
  if (result !=0)
  {
  	fprintf(stderr, "\nError sending the packet\n");
  }
  else { 
  	if(m == 'q'){
  	printf("send and recving...\n");
  	sleep(1);
  }
  if(m == 'p')
  {
  	printf("succeed\n");
  }
  }
  

}

void recv(pcap_t * handle,libnet_eth_arp_hdr *etharp_hdr,libnet_eth_arp_hdr *recv_etharp_hdr,u_int8_t * v_mac_addr)
{
	int cnt = 0;
  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    const u_char* p;
    p = packet;
    recv_etharp_hdr = (struct libnet_eth_arp_hdr *) p;
    if(recv_etharp_hdr -> ether_type == ntohs(ETHERTYPE_ARP) && recv_etharp_hdr -> ar_op == ntohs(ARPOP_REPLY) )
    {
    	for(int i=0;i<4;i++){
    		if(recv_etharp_hdr -> ar_snd_ip[i] != etharp_hdr -> ar_trgt_ip[i])
    			cnt++;
    	}
    	if(cnt == 0)
    	{
    		printf("%u bytes captured...\n", header->caplen);
    		memcpy(v_mac_addr,recv_etharp_hdr -> ar_snd_mac, sizeof(recv_etharp_hdr -> ar_snd_mac));

    		break;
    	}
    }
  }
}

void getmac(u_int8_t* mac_addr, char *argv[1])
{
	char path[64] = "/sys/class/net/";
  char str[32];
  strcat(path, argv[1]);
  strcat(path,"/address");

  FILE *fp;
 
  if(fp = fopen(path, "r")){
  	fgets(str,32,fp);
  	fclose(fp);
  }

  sscanf(str, "%x:%x:%x:%x:%x:%x",
           &mac_addr[0],
           &mac_addr[1],
           &mac_addr[2],
           &mac_addr[3],
           &mac_addr[4],
           &mac_addr[5]);
}
void getip(u_int8_t* local_ip, char *argv[1])
{
	struct ifaddrs *addrs, *tmp;
  getifaddrs(&addrs);
  
  tmp = addrs;


while (tmp) 
{
    if (tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_INET)
    {
        struct sockaddr_in *pAddr = (struct sockaddr_in *)tmp->ifa_addr;
        if((strcmp(tmp->ifa_name ,argv[1]))==0){
        	memcpy(local_ip, &pAddr->sin_addr, sizeof(pAddr->sin_addr));
        }
    }
    tmp = tmp->ifa_next;
}

freeifaddrs(addrs);
}



void usage() {
  printf("syntax: send_arp <interface> <send ip> <target ip>\n");
  printf("sample: send_arp wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char* argv[]) {
  if (argc != 4) {
    usage();
    return -1;
  }
  
  u_int8_t snd_ip[IP_ADDR_LEN];
  inet_pton(AF_INET, argv[2], snd_ip);
  u_int8_t trgt_ip[IP_ADDR_LEN]; 
  inet_pton(AF_INET, argv[3], trgt_ip);
  u_int8_t buf1[16];
  u_int8_t local_ip[IP_ADDR_LEN];
  u_int8_t buf2[16];
  u_int8_t mac_addr[ETHER_ADDR_LEN];
  u_int8_t v_mac_addr[ETHER_ADDR_LEN];
  char mode;

  	u_char *packet=(u_char*)malloc(sizeof(libnet_eth_arp_hdr));
  	struct libnet_eth_arp_hdr * etharp_hdr = (libnet_eth_arp_hdr*)malloc(sizeof(libnet_eth_arp_hdr));
	struct libnet_eth_arp_hdr * recv_etharp_hdr = (libnet_eth_arp_hdr*)malloc(sizeof(libnet_eth_arp_hdr));

  

  getip(local_ip, argv);
  getmac(mac_addr, argv);


  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }


  mode = 'q';
  send(handle,packet,etharp_hdr,recv_etharp_hdr, mode, mac_addr, v_mac_addr, local_ip, snd_ip, trgt_ip);
  recv(handle, etharp_hdr, recv_etharp_hdr, v_mac_addr);
  
  mode = 'p';
  send(handle,packet,etharp_hdr,recv_etharp_hdr, mode, mac_addr, v_mac_addr, local_ip, snd_ip, trgt_ip);
  pcap_close(handle);
  
  free(etharp_hdr);
  free(recv_etharp_hdr);
  free(packet);

  return 0;
}