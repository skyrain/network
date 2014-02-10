/*-----------------------------------------------------------------------------
 * File: sr_router.h
 * Date: ?
 * Authors: Guido Apenzeller, Martin Casado, Virkam V.
 * Contact: casado@stanford.edu
 *
 *---------------------------------------------------------------------------*/

#ifndef SR_ROUTER_H
#define SR_ROUTER_H

#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <sys/ioctl.h>
#include <unistd.h>   //close
#include "sr_protocol.h"
#ifdef VNL
#include "vnlconn.h"
#endif

typedef enum __bool { false = 0, true = 1, } bool;

/* we dont like this debug , but what to do for varargs ? */
#ifdef _DEBUG_
#define Debug(x, args...) printf(x, ## args)
#define DebugMAC(x) \
  do { int ivyl; for(ivyl=0; ivyl<5; ivyl++) printf("%02x:", \
  (unsigned char)(x[ivyl])); printf("%02x",(unsigned char)(x[5])); } while (0)
#else
#define Debug(x, args...) do{}while(0)
#define DebugMAC(x) do{}while(0)
#endif

#define INIT_TTL 255
#define PACKET_DUMP_SIZE 1024
#define MAX_HOSTS 32
#define MAX_CACHE 32
#define ICMP_ECHO_REPLY 0
#define ICMP_DEST_UNREACHABLE 3
#define ICMP_ECHO_REQUEST 8
#define ICMP_PORT_UNREACHABLE 3
#define ICMP_TIME_EXCEEDED 11
#define ICMP_CODE_DEST_HOST_UNREACHABLE 1
#define ICMP_CODE_DEST_PORT_UNREACHABLE 3
#define ICMP_CODE_DEST_PROTOCOL_UNREACHABLE 2
#define ICMP_CODE_DEST_HOST_UNKNOWN 7
#define ICMP_CODE_TRACE_CODE 0
/* forward declare */
struct sr_if;
struct sr_rt;

/* ARP Packet */
typedef struct arpPacket
{
    struct sr_ethernet_hdr et_hdr;
    struct sr_arphdr arp_hdr;
} ARPPACKET, *PARPPACKET;

struct custom_icmp{
	uint8_t type;
	uint8_t code;
	uint16_t checksum;
	uint16_t id;
	uint16_t seq;
}__attribute__ ((packed));


/* ----------------------------------------------------------------------------
 * struct sr_instance
 *
 * Encapsulation of the state for a single virtual router.
 *
 * -------------------------------------------------------------------------- */
typedef struct wait_packet
{
	uint8_t * packet;
	uint8_t len;
	uint8_t counter;
	char interface[4];
	struct wait_packet * next;
}wait_packet;

typedef struct host {
    struct sr_if * iface;
    uint8_t daddr[ETHER_ADDR_LEN];//certain interace's MAC
    uint32_t ip;
    time_t age;
    uint8_t queue;
	char * interface;
	wait_packet * wait_packet;
} Host;

typedef struct mcpacket {
        uint8_t* packet;
        uint16_t len;
        time_t age;
        uint32_t ip;
} mPacket;

struct sr_instance
{
    int  sockfd;   /* socket to server */
#ifdef VNL
    struct VnlConn* vc;
#endif
    char user[32]; /* user name */
    char host[32]; /* host name */
    char template[30]; /* template name if any */
    char auth_key_fn[64]; /* auth key filename */
    unsigned short topo_id;
    struct sockaddr_in sr_addr; /* address to server */
    struct sr_if* if_list; /* list of interfaces */
    struct sr_rt* routing_table; /* routing table */
    Host hosts[MAX_HOSTS];
    mPacket cache[MAX_CACHE];
    FILE* logfile;
};

/* structure of arp entry node */
struct arp_entry
{
    uint32_t ip_address;
    uint8_t ip[4];
    uint8_t mac_address_uint8_t[6];
    unsigned char mac_address_unsigned_char[6];
    char *interface_type;
	uint8_t counter;
    struct arp_entry *next;
    time_t timestamp;
};

// struct to hold arguments for thread activation
struct args
{
        struct sr_instance* sr;
        uint8_t* packet;
};


/*defining the arp table, which is a linked list of arp entries */
typedef struct arp_entry arp_cache_entry;

/*define global variable arp_table */
arp_cache_entry arp_table;  


struct pre_arp_entry
{
	uint32_t dst_ip;
	uint8_t wearlimit;
	struct pre_arp_entry * next;
};

typedef struct pre_arp_entry pre_arp_cache_entry;
pre_arp_cache_entry pre_arp_entry_list;

/* -- sr_main.c -- */
int sr_verify_routing_table(struct sr_instance* sr);

/* -- sr_vns_comm.c -- */
int sr_send_packet(struct sr_instance* , uint8_t* , unsigned int , const char*);
int sr_connect_to_server(struct sr_instance* ,unsigned short , char* );
int sr_read_from_server(struct sr_instance* );

/* -- sr_router.c -- */
uint8_t * retrieve_ip_address(struct sr_instance*, char*);
unsigned char * retrieve_mac_address(struct sr_instance*, char*);
bool is_new_entry(uint8_t *, char*, struct sr_instance *);
void update_arp_table(struct sr_instance *, char *, arp_cache_entry *, uint8_t *);
void sr_init(struct sr_instance* );
void sr_handlepacket(struct sr_instance* , uint8_t * , unsigned int , char* );
//void add_arp_entry(arp_cache_entry *, arp_cache_entry *);
void pretty_print_arp_table(arp_cache_entry *);
void initialize_hosts(struct sr_instance * sr);
uint32_t convert_ip_to_integer(uint8_t ip_address[]);
void sr_route_packet(struct sr_instance* sr, uint8_t * packet, int len, char* interface);
void setIPchecksum(struct ip* ip_hdr);
void send_arp_request(struct sr_instance* sr, uint32_t dst_ip);
void sr_handle_arp_packet(struct sr_instance* sr, unsigned int len, char* interface, uint8_t* packet);
//void add_host_to_cache(struct sr_instance* sr, struct ip* ip_hdr, char* interface);
struct ip* construct_ip_hdr(uint8_t *hdr);
void sr_handle_icmp_packet(struct sr_instance* sr, unsigned int len, char* interface, struct custom_icmp* icmphdr, uint8_t* packet, struct ip* ip_hdr, struct sr_ethernet_hdr* ethr_hdr);
void send_icmp_message(struct sr_instance* sr, unsigned int len, char* interface, uint8_t* packet, uint8_t type, uint8_t code);
struct ip *get_ip_hdr(uint8_t *packet);
struct ip* create_ip_hdr(uint8_t type, uint8_t ttl, uint8_t protocol, struct in_addr src, struct in_addr dest);
struct custom_icmp *get_icmp_hdr(uint8_t *packet, struct ip* ip_hdr); 
struct custom_icmp* create_icmp_hdr(uint8_t type, uint8_t code, uint16_t id, uint16_t seq); 
void setICMPchecksum(struct custom_icmp* icmphdr, uint8_t * packet, int len);
void clear_arp_cache(struct sr_instance* sr);
void packet_timeout(struct args *argument);

/* -- sr_if.c -- */
void sr_add_interface(struct sr_instance* , const char* );
void sr_set_ether_ip(struct sr_instance* , uint32_t );
void sr_set_ether_addr(struct sr_instance* , const unsigned char* );
void sr_print_if_list(struct sr_instance* );

#endif /* SR_ROUTER_H */
