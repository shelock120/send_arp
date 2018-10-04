#define LIBNET_ETH_H            0x0e    /**< Ethernet header:     14 bytes */
#define LIBNET_TCP_H            0x14    /**< TCP header:          20 bytes */
#define ETHERTYPE_IP            0x0800  /* IP protocol */
#define ETHER_ADDR_LEN			6
#define IP_ADDR_LEN				4
#define LIBNET_ARP_H            0x08    /**< ARP header w/o addrs: 8 bytes */
#define LIBNET_ARP_ETH_IP_H     0x1c    /**< ARP w/ ETH and IP:   28 bytes */
#define ETHERTYPE_ARP           0x0806  /* addr. resolution protocol */

struct libnet_ethernet_hdr
{
    u_int8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
    u_int8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
    u_int16_t ether_type;                 /* protocol */
};

struct libnet_ipv4_hdr
{
    u_int8_t ip_hl:4,      /* header length */
           ip_v:4;         /* version */
    u_int8_t ip_tos;       /* type of service */
#define IPTOS_LOWDELAY      0x10
#define IPTOS_THROUGHPUT    0x08
#define IPTOS_RELIABILITY   0x04
#define IPTOS_LOWCOST       0x02
    u_int16_t ip_len;         /* total length */
    u_int16_t ip_id;          /* identification */
    u_int16_t ip_off;

#define IP_RF 0x8000        /* reserved fragment flag */

#define IP_DF 0x4000        /* dont fragment flag */

#define IP_MF 0x2000        /* more fragments flag */ 

#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
    u_int8_t ip_ttl;          /* time to live */
    u_int8_t ip_p;            /* protocol */
    u_int16_t ip_sum;         /* checksum */
    u_int8_t ip_src[IP_ADDR_LEN]; 
    u_int8_t ip_dst[IP_ADDR_LEN]; /* source and dest address */
};

/*
 *  IP options
 */

#define IPOPT_EOL       0   /* end of option list */

#define IPOPT_NOP       1   /* no operation */   

#define IPOPT_RR        7   /* record packet route */

#define IPOPT_TS        68  /* timestamp */

#define IPOPT_SECURITY  130 /* provide s,c,h,tcc */   

#define IPOPT_LSRR      131 /* loose source route */

#define IPOPT_SATID     136 /* satnet id */

#define IPOPT_SSRR      137 /* strict source route */



 struct libnet_tcp_hdr
{
    u_int16_t th_sport;       /* source port */
    u_int16_t th_dport;       /* destination port */
    u_int32_t th_seq;          /* sequence number */
    u_int32_t th_ack;          /* acknowledgement number */
    u_int8_t th_x2:4,         /* (unused) */
           th_off:4;        /* data offset */
    u_int8_t  th_flags;       /* control flags */

#define TH_FIN    0x01      /* finished send data */

#define TH_SYN    0x02      /* synchronize sequence numbers */

#define TH_RST    0x04      /* reset the connection */

#define TH_PUSH   0x08      /* push data to the app layer */

#define TH_ACK    0x10      /* acknowledge */

#define TH_URG    0x20      /* urgent! */

#define TH_ECE    0x40
   
#define TH_CWR    0x80
    u_int16_t th_win;         /* window */
    u_int16_t th_sum;         /* checksum */
    u_int16_t th_urp;         /* urgent pointer */
};



struct libnet_eth_arp_hdr
{
    u_int8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
    u_int8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
    u_int16_t ether_type;                 /* protocol */
    u_int16_t ar_hrd;         /* format of hardware address */
#define ARPHRD_NETROM   0   /* from KA9Q: NET/ROM pseudo */
#define ARPHRD_ETHER    1   /* Ethernet 10Mbps */
#define ARPHRD_EETHER   2   /* Experimental Ethernet */
#define ARPHRD_AX25     3   /* AX.25 Level 2 */
#define ARPHRD_PRONET   4   /* PROnet token ring */
#define ARPHRD_CHAOS    5   /* Chaosnet */
#define ARPHRD_IEEE802  6   /* IEEE 802.2 Ethernet/TR/TB */
#define ARPHRD_ARCNET   7   /* ARCnet */
#define ARPHRD_APPLETLK 8   /* APPLEtalk */
#define ARPHRD_LANSTAR  9   /* Lanstar */
#define ARPHRD_DLCI     15  /* Frame Relay DLCI */
#define ARPHRD_ATM      19  /* ATM */
#define ARPHRD_METRICOM 23  /* Metricom STRIP (new IANA id) */
#define ARPHRD_IPSEC    31  /* IPsec tunnel */
    u_int16_t ar_pro;         /* format of protocol address */
    u_int8_t  ar_hln;         /* length of hardware address */
    u_int8_t  ar_pln;         /* length of protocol addres */
    u_int16_t ar_op;          /* operation type */
#define ARPOP_REQUEST       1  /* req to resolve address */
#define ARPOP_REPLY         2  /* resp to previous request */
#define ARPOP_REVREQUEST    3  /* req protocol address given hardware */
#define ARPOP_REVREPLY      4  /* resp giving protocol address */
#define ARPOP_INVREQUEST    8  /* req to identify peer */
#define ARPOP_INVREPLY      9  /* resp identifying peer */
    /* address information allocated dynamically */
    u_int8_t  ar_snd_mac[ETHER_ADDR_LEN];
    u_int8_t  ar_snd_ip[IP_ADDR_LEN];
    u_int8_t  ar_trgt_mac[ETHER_ADDR_LEN];
    u_int8_t  ar_trgt_ip[IP_ADDR_LEN];
};