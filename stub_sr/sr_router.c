/**********************************************************************
 * file:  sr_router.c 
 * date:  Mon Feb 18 12:50:42 PST 2002  
 * Contact: casado@stanford.edu 
 *
 * Description:
 * 
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing. 11
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"

#define TTL 64

arp_cache_entry arp_table;
/* 
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 * 
 *---------------------------------------------------------------------*/


void sr_init(struct sr_instance* sr) 
{
	/* REQUIRES */
	assert(sr);
	memset(&(sr->hosts[0]),0,sizeof(Host) * MAX_HOSTS);
	memset(&(sr->cache[0]),0,sizeof(mPacket) * MAX_CACHE);

	/* Add initialization code here! */

} /* -- sr_init -- */

void clear_arp_cache(struct sr_instance* sr){
	 while(1){
          sleep(5);

	struct arp_entry *traverser = &arp_table;
	struct arp_entry *follower = traverser;
	struct arp_entry *temp;
	while(traverser){
		time_t now = time(0);
		if ( now - traverser->timestamp > 15 ){
			temp = traverser;
			follower->next = traverser->next;
			traverser = traverser->next;
			if(temp != NULL){
	//			free(temp);
			}
		} else {
			follower = traverser;
			traverser = traverser->next;
		}
	}
    }


}

void packet_timeout(struct args *argument){
	while(true){
		sleep(5);
		int ii = 0;
                
  
                //scan each wait packet, decide to help them send_arp_request or delete them
                struct sr_ethernet_hdr *eth_hdr = (struct sr_ethernet_hdr *)(argument->packet);
		if(ntohs(eth_hdr->ether_type == ETHERTYPE_IP))
                {
                        //get the re_ds_ip of packdt we current handle
                        struct ip * re_iphdr = (struct ip *)(argument->packet + sizeof(struct sr_ethernet_hdr));
                        uint32_t re_ds_ip = 0;
                        struct sr_rt * rt_walker_1 = argument->sr->routing_table;
                        re_ds_ip = rt_walker_1->gw.s_addr;
                        while(rt_walker_1 != NULL)
                        {
                                if(re_iphdr->ip_dst.s_addr == rt_walker_1->dest.s_addr)
                                {
                                        re_ds_ip = rt_walker_1->dest.s_addr;
                                        break;
                                }
                                rt_walker_1 = rt_walker_1->next;
                        }


                        //scan each wait packet, if re_ds_ip == ds_ip, add their counter
                        while( ii < MAX_HOSTS)
                        {
                                struct wait_packet* curr = argument->sr->hosts[ii].wait_packet;
                                while(curr)
                                {
                                        uint32_t ds_ip = 0;
                                        struct ip * iphdr = (struct ip *)(curr->packet + sizeof(struct sr_ethernet_hdr));
                                        struct sr_rt * rt_walker = argument->sr->routing_table;
                                        ds_ip = rt_walker->gw.s_addr;
                                        while(rt_walker != NULL)
                                        {
                                                if(iphdr->ip_dst.s_addr == rt_walker->dest.s_addr)
                                                {
                                                        ds_ip = rt_walker->dest.s_addr;
                                                        break;
                                                }
                                                rt_walker = rt_walker->next;
					}


                                        if ( re_ds_ip == ds_ip)
                                                curr->counter++;

                                        curr = curr->next;
                                }
                                ii++;
                        }

                        //scan each wait packet, if couner = 5 drop it, otherwise help them send_arp_request 
                        ii = 0;
                        while( ii < MAX_HOSTS){
                                struct wait_packet* curr = argument->sr->hosts[ii].wait_packet;
                                struct wait_packet* temp;
                                while(curr){
                                        uint32_t ds_ip = 0;
                                        struct ip * iphdr = (struct ip *)(curr->packet + sizeof(struct sr_ethernet_hdr));
                                        struct sr_rt * rt_walker = argument->sr->routing_table;
                                        ds_ip = rt_walker->gw.s_addr;
                                        while(rt_walker != NULL)
                                        {
                                                if(iphdr->ip_dst.s_addr == rt_walker->dest.s_addr)
                                                {
                                                        ds_ip = rt_walker->dest.s_addr;
                                                        break;
                                                }
                                                rt_walker = rt_walker->next;
                                        }

                                        if(curr->counter == 5){
                                                temp = curr;
                                                curr = curr->next;
                                                free(temp);
                                                //send_icmp_message(sr, len, interface, packet, ICMP_DEST_UNREACHABLE, ICMP_PORT_UNREACHABLE);
                                        } else {
                                                send_arp_request(argument->sr, ds_ip);
                                                curr = curr->next;
                                        }
                                }
			ii++;
                        }
		}
	}
}

void clear_cache(struct args * argument){

	while(1){
		sleep(5);
		//		      printf("Clearing the cache\n");
		int ii = 0;

		
		//scan each wait packet, decide to help them send_arp_request or delete them
		struct sr_ethernet_hdr *eth_hdr = (struct sr_ethernet_hdr *)(argument->packet);
		
		if(ntohs(eth_hdr->ether_type == ETHERTYPE_IP))
		{
			//get the re_ds_ip of packdt we current handle
			struct ip * re_iphdr = (struct ip *)(argument->packet + sizeof(struct sr_ethernet_hdr));
			uint32_t re_ds_ip = 0;
			struct sr_rt * rt_walker_1 = argument->sr->routing_table;
			re_ds_ip = rt_walker_1->gw.s_addr;
			while(rt_walker_1 != NULL)
			{
				if(re_iphdr->ip_dst.s_addr == rt_walker_1->dest.s_addr)
				{
					re_ds_ip = rt_walker_1->dest.s_addr;
					break;
				}
				rt_walker_1 = rt_walker_1->next;
			}

			
			//scan each wait packet, if re_ds_ip == ds_ip, add their counter
			while( ii < MAX_HOSTS)
			{
				struct wait_packet* curr = argument->sr->hosts[ii].wait_packet;
				while(curr)
				{
					uint32_t ds_ip = 0;
					struct ip * iphdr = (struct ip *)(curr->packet + sizeof(struct sr_ethernet_hdr));
					struct sr_rt * rt_walker = argument->sr->routing_table;
					ds_ip = rt_walker->gw.s_addr;
					while(rt_walker != NULL)
					{
						if(iphdr->ip_dst.s_addr == rt_walker->dest.s_addr)
						{
							ds_ip = rt_walker->dest.s_addr;
							break;
						}
						rt_walker = rt_walker->next;
					}


					if ( re_ds_ip == ds_ip)
						curr->counter++;

					curr = curr->next;
				}
				ii++;
			}

			//scan each wait packet, if couner = 5 drop it, otherwise help them send_arp_request 
			ii = 0;		
			while( ii < MAX_HOSTS){
				struct wait_packet* curr = argument->sr->hosts[ii].wait_packet;
				struct wait_packet* temp;
				while(curr){
					uint32_t ds_ip = 0;
					struct ip * iphdr = (struct ip *)(curr->packet + sizeof(struct sr_ethernet_hdr));
					struct sr_rt * rt_walker = argument->sr->routing_table;
					ds_ip = rt_walker->gw.s_addr;
					while(rt_walker != NULL)
					{
						if(iphdr->ip_dst.s_addr == rt_walker->dest.s_addr)
						{
							ds_ip = rt_walker->dest.s_addr;
							break;
						}
						rt_walker = rt_walker->next;
					}

					if(curr->counter == 5){
						temp = curr;
						curr = curr->next;
						free(temp);
						//send_icmp_message(sr, len, interface, packet, ICMP_DEST_UNREACHABLE, ICMP_PORT_UNREACHABLE);
					} else {
						send_arp_request(argument->sr, ds_ip); 
						curr = curr->next;
					}
				}
				ii++;
			}
		}

		struct arp_entry *traverser = &arp_table;
		struct arp_entry *temp;
		while(traverser){
			time_t now = time(0);
			if ( now - traverser->timestamp > 15 ){
				temp = traverser;
				traverser = traverser->next;
				free(temp);
			} else {
				traverser = traverser->next;
			}
		}
		break;
	}
}



/*---------------------------------------------------------------------
 * Method: sr_handlepacke(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr, 
		uint8_t * packet/* lent */,
		unsigned int len,
		char* interface/* lent */)
{
	/* REQUIRES */
	assert(sr);
	assert(packet);
	assert(interface);
	struct args *argument = (struct args *)malloc(64);
//	memcpy(argument->sr, sr, sizeof(struct sr_instance));
//	memcpy(argument->packet, packet, len);
	argument->sr = sr;
	argument->packet = packet;

	pthread_t thread1;
	pthread_create( &thread1, NULL, packet_timeout, (void*) argument);

	printf("\n\n Packet received: \n");
	struct sr_if *eth_if = (struct sr_if *) sr_get_interface(sr, interface);
	if(eth_if) {
		printf("进入interface: %s \n", eth_if->name);
	} else {
		printf("!!! Invalid Interface: %s \n", interface);
	}
	
	//retrieve router's info and initialize the hosts[]
	initialize_hosts(sr);

	/* Ethernet Header */
	struct sr_ethernet_hdr *eth_hdr = (struct sr_ethernet_hdr *) packet;

	switch(ntohs(eth_hdr->ether_type))
	{
		case ETHERTYPE_ARP:
			printf("1 - 接收 ARP packet \n");
			sr_handle_arp_packet(sr, len, interface, packet);
			break;
		case ETHERTYPE_IP:
			{

				struct ip *iphdr;
				iphdr = construct_ip_hdr(packet);
			
				//check IP packet is for the router or not
				struct sr_if *interfaces = sr->if_list;
				while(interfaces) 
				{
					if (iphdr->ip_dst.s_addr == interfaces->ip) break;
					interfaces = interfaces->next;
				}

				//If IP packet is for the router
				if (interfaces)
				{
					printf("2 - 终点: Router\n");
					struct custom_icmp* my_icmp = (struct custom_icmp*)(packet + sizeof(struct sr_ethernet_hdr) + iphdr->ip_hl * 4); 

					//If is ICMP echo request, send ICMP echo reply
					if(iphdr->ip_p == IPPROTO_ICMP && my_icmp->type == ICMP_ECHO_REQUEST)
					{ 
						my_icmp = get_icmp_hdr(packet, iphdr);
						printf("2.1 - 接收 ICMP Echo Request, 发送 ICMP ECHO Reply\n");
						sr_handle_icmp_packet(sr, len, interface, my_icmp, packet, iphdr, (struct sr_ethernet_hdr *) packet);
					}
					//else If is not ICMP echo request
					//1.else If is TCP, UDP packet, sent Port unreacheable ICMP
					//2.else if is not TCP,UDP packet, sent Port unreachable ICMP
					else
					{
						printf("2.2 - 接受 非 ICMP Request 的IP packet\n");
						//If is TCP or UDP packet
					    if(iphdr->ip_p == IPPROTO_TCP || iphdr->ip_p == IPPROTO_UDP)
							send_icmp_message(sr, len, interface, packet, ICMP_DEST_UNREACHABLE, ICMP_PORT_UNREACHABLE);
						//just reply as port unreachable
					//	else
					//		send_icmp_message(sr, len, interface, packet, ICMP_DEST_UNREACHABLE, ICMP_PORT_UNREACHABLE);
					}
				}
				//If IP packet is not for the router
				else
				{
					//if the packet is in wrong destination
					//根据packet的dst ip确定next hop的ip
					//再用该ip搜寻arp table
					struct sr_rt * rt_walker = sr->routing_table;
					struct ip * tt = (struct ip *)(packet + sizeof(struct sr_ethernet_hdr));
					struct custom_icmp * tt_ic = (struct custom_icmp *)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip));
					while(rt_walker != NULL)
					{
						if(tt->ip_dst.s_addr == rt_walker->dest.s_addr)
						{
							break;
						}
						rt_walker = rt_walker->next;
					}

					if(rt_walker != NULL || tt_ic->type != ICMP_ECHO_REQUEST)
					{

						printf("3 - 终点：不是 Router\n");
						if(iphdr->ip_ttl > 1) 
						{
							printf("3.1 - 继续传递\n");
							sr_route_packet(sr,packet,len,interface);
						}
						else 
						{
							printf("3.2 - 超时, 传回去\n");
							send_icmp_message(sr, len, interface, packet, ICMP_TIME_EXCEEDED, 0);
						}
					}
					else
					{
						send_icmp_message(sr, len, interface, packet, ICMP_DEST_UNREACHABLE, ICMP_PORT_UNREACHABLE);
					}
				}
			}

			break;

		default:
			{
				printf("4 - 接收的不是 ICMP 也不是 ARP\n");
				send_icmp_message(sr, len, interface, packet, ICMP_DEST_UNREACHABLE, ICMP_PORT_UNREACHABLE);
			}
	}

}/* end sr_ForwardPacket */



/*--------------------------------------------------------------------- 
 * Method:
 *
 *---------------------------------------------------------------------*/

//Only handle sending ICMP echo request
void sr_handle_icmp_packet(struct sr_instance* sr, unsigned int len, char* interface, struct custom_icmp* icmphdr, uint8_t* packet, struct ip* ip_hdr, struct sr_ethernet_hdr* ethr_hdr)
{
	//construct packet
	uint8_t * tmp_packet = (uint8_t *)malloc(sizeof(uint8_t) * len);
	memcpy(tmp_packet, packet, len);
	struct sr_ethernet_hdr * tmp_ethr_hdr = (struct sr_ethernet_hdr *)tmp_packet;
	memcpy(tmp_packet + 6, ethr_hdr->ether_dhost, 6);
	memcpy(tmp_packet, ethr_hdr->ether_shost, 6);
	tmp_ethr_hdr->ether_type = htons(ETHERTYPE_IP);
	
	struct ip * tmp_ip_hdr = (struct ip *)(tmp_packet + sizeof(struct sr_ethernet_hdr));
	tmp_ip_hdr->ip_dst = ip_hdr->ip_src;
	tmp_ip_hdr->ip_src = ip_hdr->ip_dst;

//	ip_hdr->ip_src.s_addr = (ip_hdr->ip_dst.s_addr);
//	ip_hdr->ip_dst.s_addr = *dest;
	
	struct custom_icmp* tmp_icmphdr = get_icmp_hdr(tmp_packet, tmp_ip_hdr);
	tmp_icmphdr->type = ICMP_ECHO_REPLY;
	
//	tmp_icmphdr->checksum = htons(0);
	setICMPchecksum(tmp_icmphdr, tmp_packet + sizeof (struct sr_ethernet_hdr) + tmp_ip_hdr->ip_hl * 4, len - sizeof (struct sr_ethernet_hdr) - tmp_ip_hdr->ip_hl * 4);
	
	//set the ICMP echo reply original TTL, and calculate the IP checksum
	tmp_ip_hdr->ip_ttl = TTL;
	
//	tmp_ip_hdr->ip_sum = htons(0);
	setIPchecksum(tmp_ip_hdr);

	printf("Echo request from %s to ", inet_ntoa(tmp_ip_hdr->ip_src));
	printf("%s.\n", inet_ntoa(tmp_ip_hdr->ip_dst));
	
	sr_send_packet(sr, tmp_packet, len, interface);

	//发送数据后马上free,发送的数据和packet??
	free(tmp_packet);
}

struct custom_icmp *get_icmp_hdr(uint8_t *packet, struct ip* ip_hdr) {
	return (struct custom_icmp *) (packet + sizeof (struct sr_ethernet_hdr) + ip_hdr->ip_hl * 4);
}



void send_icmp_message(struct sr_instance* sr, unsigned int len, char* interface, uint8_t* packet, uint8_t type, uint8_t code) 
{
	struct ip* in_ip_hdr = get_ip_hdr(packet);
	uint8_t * outpack =(uint8_t *)malloc(sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + 4 + 4 + (in_ip_hdr->ip_hl * 4 + 8));	


	struct sr_ethernet_hdr * out_eth_hdr = (struct sr_ethernet_hdr *) outpack;

	memcpy(outpack, packet + 6, 6);
	memcpy(outpack + 6, packet, 6);
//??ntohs or htons
	out_eth_hdr->ether_type = htons(ETHERTYPE_IP);
	
	//有给tmp_ip分配空间,用完后free
	struct ip* tmp_ip = create_ip_hdr(0, TTL, IPPROTO_ICMP, in_ip_hdr->ip_dst, in_ip_hdr->ip_src);
	
	struct ip* out_ip_hdr = (struct ip *) (outpack + sizeof (struct sr_ethernet_hdr));
	memcpy(outpack + sizeof (struct sr_ethernet_hdr), tmp_ip, 20);

	out_ip_hdr->ip_id = in_ip_hdr->ip_id;

	// create and fill the sent icmp header 
	struct custom_icmp * out_icmp = (struct custom_icmp *) (outpack + sizeof (struct sr_ethernet_hdr) + 20);
	//有给tmpicmp分配空间，用完后free
//	struct custom_icmp* tmpicmp =(struct custom_icmp *) malloc(sizeof (struct custom_icmp));
	out_icmp->type = type;
	out_icmp->code = code;
	out_icmp->id = htons(0);
	out_icmp->seq = htons(0);

//	memcpy(out_icmp, tmpicmp, 8);
//	free(tmpicmp);
	
    //fill internet header + first 8 bytes of hte original datagram's data	
	memcpy(((uint8_t *) out_icmp) + 8, in_ip_hdr, in_ip_hdr->ip_hl * 4 + 8);

//??ntohs or htons	
	out_ip_hdr->ip_len = htons(20 + 8 + in_ip_hdr->ip_hl * 4 + 8);

	// calculate checksums for message 
//	out_icmp->checksum = htons(0);
	setICMPchecksum(out_icmp, outpack + sizeof (struct sr_ethernet_hdr) + 20, 8 + in_ip_hdr->ip_hl * 4 + 8);
	
//	out_ip_hdr->ip_sum = htons(0);
	setIPchecksum(out_ip_hdr);
	
	sr_send_packet(sr, outpack, sizeof (struct sr_ethernet_hdr) + 20 + 8 + in_ip_hdr->ip_hl * 4 + 8, interface);
	
	free(tmp_ip);
	free(outpack);
}

	struct ip *get_ip_hdr(uint8_t *packet) {
		return (struct ip *) (packet + sizeof (struct sr_ethernet_hdr));
	}

	struct ip* create_ip_hdr(uint8_t type, uint8_t ttl, uint8_t protocol, struct in_addr src, struct in_addr dest) {
		struct ip* ip_hdr = malloc(20);
		ip_hdr->ip_v = 4;
		ip_hdr->ip_ttl = ttl;
		ip_hdr->ip_hl = 5;
		ip_hdr->ip_p = protocol;
		ip_hdr->ip_src = src;
		ip_hdr->ip_dst = dest;
		ip_hdr->ip_off = 0;
		ip_hdr->ip_tos = type;
		return ip_hdr;
	}

	struct custom_icmp* create_icmp_hdr(uint8_t type, uint8_t code, uint16_t id, uint16_t seq) {
		struct custom_icmp* icmp_hdr =(struct custom_icmp *) malloc(sizeof (struct custom_icmp));
		icmp_hdr->type = type;
		icmp_hdr->code = code;
		icmp_hdr->id = id;
		icmp_hdr->seq = seq;

		uint16_t sum = 0;
		sum = ((type << 8)&0xFF00) + code;
		sum = sum + id + seq;

		return icmp_hdr;
	}


	uint32_t convert_ip_to_integer(uint8_t ip_address[]){
		int mask = 0xFF;
		uint32_t result = 0;
		result = ip_address[0] & mask;
		result += ((ip_address[1] & mask) << 8);
		result += ((ip_address[2] & mask) << 16);
		result += ((ip_address[3] & mask) << 24);
		return result;
	}

void initialize_hosts(struct sr_instance* sr)
	{
		struct sr_if* if_walker = 0;
		if(sr->if_list == 0)
		{
			printf("Interface list empty \n");
			return ;
		}
		if_walker = sr->if_list;

		int i = 0;
		while(if_walker)
		{
			memcpy(sr->hosts[i].daddr, (uint8_t *)if_walker->addr, ETHER_ADDR_LEN);
			sr->hosts[i].ip = if_walker->ip;
		    sr->hosts[i].iface = if_walker;
			sr->hosts[i].interface = if_walker->name;
			i++;

			if_walker = if_walker->next;
		}
	}

	void setIPchecksum(struct ip* ip_hdr) {
		uint32_t sum = 0;
		ip_hdr->ip_sum = 0;

		uint16_t* tmp = (uint16_t *) ip_hdr;

		int i;
		for (i = 0; i < ip_hdr->ip_hl * 2; i++) {
			sum = sum + tmp[i];
		}

		sum = (sum >> 16) + (sum & 0xFFFF);
		sum = sum + (sum >> 16);

		ip_hdr->ip_sum = ~sum;
	}

	void setICMPchecksum(struct custom_icmp* icmphdr, uint8_t * packet, int len) {
		uint32_t sum = 0;
		icmphdr->checksum = 0;
		uint16_t* tmp = (uint16_t *) packet;

		int i;
		for (i = 0; i < len / 2; i++) {
			sum = sum + tmp[i];
		}

		sum = (sum >> 16) + (sum & 0xFFFF);
		sum = sum + (sum >> 16);

		icmphdr->checksum = ~sum;
	}

	struct ip* construct_ip_hdr(uint8_t *packet){
		return (struct ip*) (packet + sizeof(struct sr_ethernet_hdr));	
	}

	void sr_handle_arp_packet(struct sr_instance* sr, unsigned int len, char* interface, uint8_t* packet)
	{
		//之后free tmp_packet
		uint8_t * tmp_packet = (uint8_t *)malloc(sizeof(uint8_t) * len);
		memcpy(tmp_packet, packet, len);	
		struct sr_ethernet_hdr* ethr_hd = (struct sr_ethernet_hdr *)tmp_packet;
		struct sr_arphdr* arp_hdr = (struct sr_arphdr *) (tmp_packet + sizeof (struct sr_ethernet_hdr));

		//If is an ARP request
		if (ntohs(arp_hdr->ar_op) == ARP_REQUEST) 
		{
			//update the ARP cache table
			update_arp_table(sr, interface, &arp_table, tmp_packet);	
			//check this ARP is destined for the router or not
			bool IS_FOR_ROUTER = false;
			int host_no = -1;		
			struct sr_if * iface = sr->if_list;
			while (iface) 
			{
				if (iface->ip == arp_hdr->ar_tip)
				{
					IS_FOR_ROUTER = true;
					int j;
					//know which host the ARP enter in in the router.
					for (j = 0; j < MAX_HOSTS; j++)
					{
						if (sr->hosts[j].ip == arp_hdr->ar_tip)
						{
							host_no = j;
							break;
						}
					}
					break;
				}
				iface = iface->next;
			}

			//This ARP request is for router
			if (IS_FOR_ROUTER)
			{
				//construct ARP reply packet
				struct sr_arphdr* arp_reply = (struct sr_arphdr *) (tmp_packet + sizeof (struct sr_ethernet_hdr));
				memcpy(ethr_hd->ether_dhost, ethr_hd->ether_shost, 6);
				memcpy(ethr_hd->ether_shost, sr->hosts[host_no].daddr, 6);
				ethr_hd->ether_type = htons(ETHERTYPE_ARP);
				arp_reply->ar_hrd = htons(ARPHDR_ETHER);
				arp_reply->ar_pro = htons(ETHERTYPE_IP);
				arp_reply->ar_hln = 6;
				arp_reply->ar_pln = 4;
				arp_reply->ar_op = htons(ARP_REPLY);
				memcpy(arp_reply->ar_sha, sr_get_interface(sr,interface)->addr, sizeof (ethr_hd->ether_dhost));
				//since already swap between source and destin, we use ether_dhost
				memcpy(arp_reply->ar_tha, ethr_hd->ether_dhost, 6);
				uint32_t tmp = arp_reply->ar_tip;
				arp_reply->ar_tip = arp_reply->ar_sip;
				arp_reply->ar_sip = tmp;

				printf("Sending ARP REPLY!!\n");
				sr_send_packet(sr, tmp_packet, len, interface);
				free(tmp_packet);
			}
		}
		//if is an arp reply, 
		//1. update the arp table
		//2. send waiting list ok to sent packets according to new ARP table
		else if (ntohs(arp_hdr->ar_op) == ARP_REPLY) 
		{	
			int i, j, host_no;
			//know which host the ARP enter in in the router.
			for (j = 0; j < MAX_HOSTS; j++)
			{
				if (sr->hosts[j].ip == arp_hdr->ar_tip)
				{
					host_no = j;
					break;
				}
			}

			printf("*******网卡 %s got ARP reply*****\n", interface);
			//update the ARP cache table
			update_arp_table(sr, interface, &arp_table, tmp_packet);	
			free(tmp_packet);
			
			//Release which good to be sent in the waiting list
			//just scan the hosts in the running inteface
			for(i = 0; i < MAX_HOSTS; i++)
			{
				wait_packet * packet_walker = sr->hosts[i].wait_packet;
				//If 0 wait packet
				if(!packet_walker)
				{
					;
				}
				//else if >=1 wait packet
				else
				{	
					//If only 1 wait packet
					if(!packet_walker->next)
					{
						arp_cache_entry * table_walker = &arp_table;

						struct ip * packet_iphdr = (struct ip *)(packet_walker->packet + sizeof(struct sr_ethernet_hdr));
						bool IS_DELETE = false;

//看arp table
						arp_cache_entry * ttable_walker = table_walker;
						while(ttable_walker != NULL)
						{
							printf("------%lu\n", (unsigned long)ttable_walker->ip_address);
							printf("----%s\n", ttable_walker->interface_type);
							printf("**** -----table has**********\n");


							ttable_walker = ttable_walker->next;
						}


						//根据packet的dst ip确定next hop的ip
						//再用该ip搜寻arp table
						uint32_t exist_arp_ip = 0;
						struct sr_rt * rt_walker = sr->routing_table;
						exist_arp_ip = rt_walker->gw.s_addr;

						while(rt_walker != NULL)
						{
							if(packet_iphdr->ip_dst.s_addr == rt_walker->dest.s_addr)
							{
								exist_arp_ip = rt_walker->dest.s_addr;
								break;
							}
							rt_walker = rt_walker->next;
						}


						while(table_walker != NULL)
						{
							printf("------%lu\n", (unsigned long)table_walker->ip_address);
							printf("----%lu\n", (unsigned long)packet_iphdr->ip_dst.s_addr);

							if(table_walker->ip_address == exist_arp_ip)
							{
								printf("****table has**********");
								uint8_t * tp_packet = (uint8_t *)malloc(sizeof(uint8_t) * packet_walker->len);
								memcpy(tp_packet, packet_walker->packet, packet_walker->len);
								
								//the pacekt's src and dst IP remains same
								printf("Table: %s\n", table_walker->interface_type);
								printf("Now interface: %s\n", interface);
								//checksum
								struct ip * out_ip_hdr = (struct ip *)(tp_packet + sizeof(struct sr_ethernet_hdr));
								uint8_t t = out_ip_hdr->ip_ttl -1;
								out_ip_hdr->ip_ttl = t;
								setIPchecksum(out_ip_hdr);

								//do outside transfer
								if(strncmp(table_walker->interface_type, interface, 4) == 0)
								{
									printf("outside transfer\n");
									//src MAC: ing interface's MAC
									memcpy(tp_packet + 6, sr->hosts[host_no].daddr, 6);
									//dst MAC: dst IP 's MAC----table_walker's mac
									memcpy(tp_packet, table_walker->mac_address_uint8_t, 6);
									sr_send_packet(sr, tp_packet, packet_walker->len, sr->hosts[host_no].interface);
								}
								//inner transfer
								else
								{
									printf("innner transfer\n");
									int k;
									for(k = 0; k < MAX_HOSTS; k++)
									{
										if(strcmp(sr->hosts[k].interface, table_walker->interface_type) == 0)
										{
											memcpy(tp_packet + 6, sr->hosts[k].daddr, 6);
											break;
										}
									}
									memcpy(tp_packet, table_walker->mac_address_uint8_t, 6);
									sr_send_packet(sr, tp_packet, packet_walker->len, sr->hosts[k].interface);
								}	
								
								printf("队列只 1 个 Release  包\n");

								if(out_ip_hdr->ip_p ==IPPROTO_ICMP)
								{
									struct custom_icmp * tp_icmphdr = get_icmp_hdr(tp_packet, out_ip_hdr);
									printf("类型: %d", tp_icmphdr->type);
								}
								free(tp_packet);
								IS_DELETE = true;
								break;
							}//if find to send 
							table_walker = table_walker->next;
						}//while check next table ele

						if(IS_DELETE)
						{
							sr->hosts[i].wait_packet = NULL;
							free(packet_walker);
						}

					}
					//else > 1 wait packet
					else
					{
						//scan all the wait packets at certain host
						//scan exclude for the 1st ele
						while(packet_walker->next)
						{
							arp_cache_entry * table_walker = &arp_table;
							struct ip * packet_iphdr = (struct ip *)(packet_walker->next->packet + sizeof(struct sr_ethernet_hdr));
							bool IS_DELETE = false;

							//根据packet的dst ip确定next hop的ip
							//再用该ip搜寻arp table
							uint32_t exist_arp_ip = 0;
							struct sr_rt * rt_walker = sr->routing_table;
							exist_arp_ip = rt_walker->gw.s_addr;

							while(rt_walker != NULL)
							{
								if(packet_iphdr->ip_dst.s_addr == rt_walker->dest.s_addr)
								{
									exist_arp_ip = rt_walker->dest.s_addr;
									break;
								}
								rt_walker = rt_walker->next;
							}

							//see if ok to send the wait packet
							while(table_walker)
							{
								if(table_walker->ip_address == exist_arp_ip)
								{
									uint8_t * tp_packet = (uint8_t *)malloc(sizeof(uint8_t) * packet_walker->next->len);
									memcpy(tp_packet, packet_walker->next->packet, packet_walker->next->len);
									//checksum
									struct ip * out_ip_hdr = (struct ip *)(tp_packet + sizeof(struct sr_ethernet_hdr));
									uint8_t t = out_ip_hdr->ip_ttl - 1;
									out_ip_hdr->ip_ttl = t;
									setIPchecksum(out_ip_hdr);

									//the pacekt's src and dst IP remains same
									printf("Table: %s\n", table_walker->interface_type);
									printf("Now interface: %s\n", interface);

									//do outside transfer
									if(strncmp(table_walker->interface_type, interface, 4) == 0)
									{
										printf("outside transfer\n");
										//src MAC: ing interface's MAC
										memcpy(tp_packet + 6, sr->hosts[host_no].daddr, 6);
										//dst MAC: dst IP 's MAC
										memcpy(tp_packet, table_walker->mac_address_uint8_t, 6);
										sr_send_packet(sr, tp_packet, packet_walker->next->len, sr->hosts[host_no].interface);
									}
									//inner transfer
									else
									{
										printf("innner transfer\n");
										//dst MAC: cha hosts shui you interface == table_walker->interface_type
										int k;
										for(k = 0; k < MAX_HOSTS; k++)
										{
											if(strcmp(sr->hosts[k].interface, table_walker->interface_type) == 0)
											{
												memcpy(tp_packet + 6, sr->hosts[k].daddr, 6);
												break;
											}
										}
										memcpy(tp_packet, table_walker->mac_address_uint8_t, 6);
										sr_send_packet(sr, tp_packet, packet_walker->next->len, sr->hosts[k].interface);
									}	

									printf("队列 > 1 个 Release 包\n");
									free(tp_packet);
									IS_DELETE = true;
									break;
								}
								table_walker = table_walker->next;	
							}

							if(IS_DELETE)
							{
//??may have error in delete
								wait_packet * delete_guy = packet_walker->next;
								packet_walker->next = packet_walker->next->next;
								
								free(delete_guy);
							}
							else
							{
								packet_walker = packet_walker->next; 
							}
						}

						arp_cache_entry * table_walker = &arp_table;
						struct ip * packet_iphdr = (struct ip *)(sr->hosts[i].wait_packet->packet + sizeof(struct sr_ethernet_hdr));

						//check the 1st ele
						bool IS_DELETE = false;
						//根据packet的dst ip确定next hop的ip
						//再用该ip搜寻arp table
						uint32_t exist_arp_ip = 0;
						struct sr_rt * rt_walker = sr->routing_table;
						exist_arp_ip = rt_walker->gw.s_addr;

						while(rt_walker != NULL)
						{
							if(packet_iphdr->ip_dst.s_addr == rt_walker->dest.s_addr)
							{
								exist_arp_ip = rt_walker->dest.s_addr;
								break;
							}
							rt_walker = rt_walker->next;
						}

						//see if ok to send the wait packet
						while(table_walker)
						{
							if(table_walker->ip_address == exist_arp_ip)
							{
								uint8_t * tp_packet = (uint8_t *)malloc(sizeof(uint8_t) * sr->hosts[i].wait_packet->len);
								memcpy(tp_packet, sr->hosts[i].wait_packet->packet, sr->hosts[i].wait_packet->len);
								//the pacekt's src and dst IP remains same
								printf("Table: %s\n", table_walker->interface_type);
								printf("Now interface: %s\n", interface);
								struct ip * out_ip_hdr = (struct ip *)(tp_packet + sizeof(struct sr_ethernet_hdr));
								uint8_t t = out_ip_hdr->ip_ttl - 1;
								out_ip_hdr->ip_ttl = t;
								setIPchecksum(out_ip_hdr);

								//do outside transfer
								if(strncmp(table_walker->interface_type, interface, 4) == 0)
								{
									printf("outside transfer\n");
									//src MAC: ing interface's MAC
									memcpy(tp_packet + 6, sr->hosts[host_no].daddr, 6);
									//dst MAC: dst IP 's MAC
									memcpy(tp_packet, table_walker->mac_address_uint8_t, 6);
									sr_send_packet(sr, tp_packet, sr->hosts[i].wait_packet->len, sr->hosts[host_no].interface);
								}
								//inner transfer
								else
								{
									printf("innner transfer\n");
									//dst MAC: cha hosts shui you interface == table_walker->interface_type
									int k;
									for(k = 0; k < MAX_HOSTS; k++)
									{
										if(strcmp(sr->hosts[k].interface, table_walker->interface_type) == 0)
										{
											memcpy(tp_packet + 6, sr->hosts[k].daddr, 6);
											break;
										}
									}
									memcpy(tp_packet, table_walker->mac_address_uint8_t, 6);
									sr_send_packet(sr, tp_packet, sr->hosts[i].wait_packet->len, sr->hosts[k].interface);
								}	
								//checksum
								printf("队列 > 1 并且 在头部 Release 包\n");
								free(tp_packet);

								IS_DELETE = true;
								break;
							}
							table_walker = table_walker->next;	
						}

						if(IS_DELETE)
						{
							wait_packet * delete_guy = sr->hosts[i].wait_packet;
							sr->hosts[i].wait_packet = sr->hosts[i].wait_packet->next;
							free(delete_guy);
						}
					}//> 1

				}//>=1
			}				//for all the hosts
		}//else if is ARP reply
	}//func end


//only call this func, when arrive IP packet is not for the router
void sr_route_packet(struct sr_instance * sr, uint8_t * packet, int len, char* interface)
{
	int j, host_no;

	//understand which interface the IP packet reach for the router
	//know which host the ARP enter in in the router.
	for (j = 0; j < MAX_HOSTS; j++)
	{
		if (!memcmp(sr->hosts[j].interface, interface, 4))
		{
			host_no = j;
			break;
		}
	}

	//1. check ARP cache table
	//2.check If the desin MAC in the table
	//2.1 not in, hold the packet, send ARP request
	arp_cache_entry * list_arp = &arp_table;
	while(list_arp != NULL)
	{
		printf("arp table ip: %lu\n", list_arp->ip_address);
		printf("arp table interface: %s\n", list_arp->interface_type);
		list_arp = list_arp->next;
	}
	
	struct ip * list_ip = (struct ip*)(packet + sizeof(struct sr_ethernet_hdr));
	printf("this packet's dst ip: %lu\n", list_ip->ip_dst.s_addr);


	if(is_new_entry(packet, interface, sr))
	{

		//之后要free, construct the future to be sent packet
		uint8_t * tmp_packet = (uint8_t *)malloc(sizeof(uint8_t) * len);
		memcpy(tmp_packet, packet, len);
		struct ip* ip_hdr = (struct ip *) (tmp_packet + sizeof(struct sr_ethernet_hdr));
			
		//get next hop ip addr
		uint32_t ds_ip = 0;
		struct ip * iphdr =(struct ip *)(packet + sizeof(struct sr_ethernet_hdr));
		struct sr_rt * rt_walker = sr->routing_table;

		//default next hop is 172.29.9.201
		ds_ip = rt_walker->gw.s_addr;

		while(rt_walker != NULL)
		{
			if(iphdr->ip_dst.s_addr == rt_walker->dest.s_addr)
			{
				ds_ip = rt_walker->dest.s_addr;
				break;
			}
			rt_walker = rt_walker->next;
		}
		
		//create the plug in wait_packet
		wait_packet * new_guy = (wait_packet *)malloc(sizeof(wait_packet));
		new_guy->next = NULL;
		new_guy->packet = (uint8_t *)malloc(len);
		memcpy(new_guy->packet,  tmp_packet, len);
		memcpy(new_guy->interface, interface, 4);
		new_guy->len = len;
		new_guy->counter = 0;

		//If 0 wait_packet,add the 1st wait packet
		if(!sr->hosts[host_no].wait_packet)
			sr->hosts[host_no].wait_packet = new_guy;
		//else if >= 1 wait packet
		else
		{
			new_guy->next = sr->hosts[host_no].wait_packet->next;
			sr->hosts[host_no].wait_packet->next = new_guy;
		}
		
		printf("本机 IP %lu, 本机 网卡 %s \n", sr->hosts[host_no].ip, interface);
		printf("谁有 %lu  的MAC\n", ip_hdr->ip_dst.s_addr);

		send_arp_request(sr, ds_ip);
		free(tmp_packet);

	}
	//2.2 already in ARP table
	else
	{
		//之后要free, construct the future to be sent packet
		uint8_t * tmp_packet = (uint8_t *)malloc(sizeof(uint8_t) * len);
		memcpy(tmp_packet, packet, len);
		struct ip* ip_hdr = (struct ip *) (tmp_packet + sizeof(struct sr_ethernet_hdr));

		printf("传递\n");
		struct ip * packet_iphdr = (struct ip *)(tmp_packet + sizeof(struct sr_ethernet_hdr));
		printf("源头 - packet_iphdr %lu\n", packet_iphdr->ip_src.s_addr);

		uint8_t t = packet_iphdr->ip_ttl - 1;
		packet_iphdr->ip_ttl = t;
		setIPchecksum(packet_iphdr);

		//根据packet的dst ip确定next hop的ip
		//再用该ip搜寻arp table
		uint32_t exist_arp_ip = 0;
		struct sr_rt * rt_walker = sr->routing_table;
		exist_arp_ip = rt_walker->gw.s_addr;
		
		while(rt_walker != NULL)
		{
			if(packet_iphdr->ip_dst.s_addr == rt_walker->dest.s_addr)
			{
				exist_arp_ip = rt_walker->dest.s_addr;
				break;
			}
			rt_walker = rt_walker->next;
		}

		arp_cache_entry * table_walker = &arp_table;
		while(table_walker)
		{
			if(table_walker->ip_address == exist_arp_ip)
			{
				break;
			}
			table_walker = table_walker->next;
		}

		//do outside transfer
		if(strncmp(table_walker->interface_type, interface, 4) == 0)
		{
			printf("outside transfer\n");
			//assgin router's in  MAC as src ether MAC
			memcpy(tmp_packet + 6, sr->hosts[host_no].daddr, 6);
			memcpy(tmp_packet, table_walker->mac_address_uint8_t, 6);	
			sr_send_packet(sr, tmp_packet, len, interface);
		}
		//inner transfer
		else
		{
			printf("inner transfer\n");
			//src MAC: cha hosts shui you interface == table_walker->inter     face_type
			int k;
			for(k = 0; k < MAX_HOSTS; k++)
			{
				if(strcmp(sr->hosts[k].interface, table_walker->interface_type) == 0)
				{
					memcpy(tmp_packet + 6, sr->hosts[k].daddr, 6);
					break;
				}
			}
			memcpy(tmp_packet, table_walker->mac_address_uint8_t, 6);
			sr_send_packet(sr, tmp_packet, len, sr->hosts[k].interface);
		}

	}

}


void send_arp_request(struct sr_instance * sr, uint32_t dst_ip) 
{
	printf("sending arp request\n");
	uint8_t * packet = (uint8_t *)malloc(sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arphdr));

	struct sr_ethernet_hdr * eth_hdr = (struct sr_ethernet_hdr *) packet;
	struct sr_arphdr * arp_hdr = (struct sr_arphdr *) (packet + sizeof (struct sr_ethernet_hdr));

	eth_hdr->ether_type = ntohs(ETHERTYPE_ARP);
	eth_hdr->ether_dhost[0] = 255;
	eth_hdr->ether_dhost[1] = 255;
	eth_hdr->ether_dhost[2] = 255;
	eth_hdr->ether_dhost[3] = 255;
	eth_hdr->ether_dhost[4] = 255;
	eth_hdr->ether_dhost[5] = 255;
	
	arp_hdr->ar_hrd = ntohs(1);
	arp_hdr->ar_op = ntohs(ARP_REQUEST);
	arp_hdr->ar_pro = ntohs(ETHERTYPE_IP);
	arp_hdr->ar_hln = 6;
	arp_hdr->ar_pln = 4;
	arp_hdr->ar_tip = dst_ip;
	
	//according to next hop ip, search routing table,know from which interface to
	//send the arp request
	struct sr_rt * rt_walker = sr->routing_table;
	char* arp_src_interface = (char *)malloc(sizeof(rt_walker->interface));
	
	while(rt_walker != NULL)
	{
		if(rt_walker->dest.s_addr == 0)
		{
			if(rt_walker->gw.s_addr == dst_ip)
			{
				strcpy(arp_src_interface, rt_walker->interface);
				break;
			}
		}
		else
		{
			if(rt_walker->dest.s_addr == dst_ip)
			{
				strcpy(arp_src_interface, rt_walker->interface);
				break;
			}
		}
		rt_walker = rt_walker->next;
	}

	//根据arp source interface,找到相应的source ip,和source MAC
	struct sr_if * iface = sr->if_list;
	while (iface)
	{
		if(strcmp(iface->name, arp_src_interface) == 0)
		{

			//设置ARP request的源头MAC为该interface的MAC
			int j;
			for (j = 0; j < ETHER_ADDR_LEN; j++)
			{
				arp_hdr->ar_sha[j] = iface->addr[j];
				eth_hdr->ether_shost[j] = arp_hdr->ar_sha[j];
			}

			printf("ARP 请求知道 IP %lu 的MAC\n", arp_hdr->ar_tip);

			//设置ARP Request的源IP为interface的IP
			arp_hdr->ar_sip = iface->ip;
			//get next hop ip addr
     		sr_send_packet(sr, packet, sizeof (struct sr_ethernet_hdr) + sizeof (struct sr_arphdr), iface->name);

		}
		iface = iface->next;
	}

	free(packet);
}


//only called when packet is IP packet,
	bool is_new_entry(uint8_t * packet, char* interface, struct sr_instance * sr)
	{
		//1.build the possible arp entry
		//2.check whether this entry already in arp cache table
		uint32_t ds_ip = 0;
		struct ip * iphdr =(struct ip *)(packet + sizeof(struct sr_ethernet_hdr));
		struct sr_rt * rt_walker = sr->routing_table;
		
		//default next hop is 172.29.9.201
		ds_ip = rt_walker->gw.s_addr;
		
		while(rt_walker != NULL)
		{
			if(iphdr->ip_dst.s_addr == rt_walker->dest.s_addr)
			{
				ds_ip = rt_walker->dest.s_addr;
				break;
			}
			rt_walker = rt_walker->next;
		}

		bool IS_NEW_ENTRY = true;
		
		//search if entry already exists
		arp_cache_entry* arp_pointer = &arp_table;
		while(arp_pointer != NULL)
		{
			if (arp_pointer->ip_address == ds_ip)
			{
				IS_NEW_ENTRY = false;
				break;
			}
			arp_pointer = arp_pointer->next;
		}
		
		return IS_NEW_ENTRY;
	}

	void update_arp_table(struct sr_instance * sr, char * interface, arp_cache_entry * arp_table, uint8_t * packet)
	{
		arp_cache_entry * entry = (arp_cache_entry *)malloc(sizeof(arp_cache_entry)); 
		//1.build the possible arp entry
		//2.check whether this entry already in arp cache table
		//根据packet的dst ip, 确定next hop为与router相连的哪个机器的那个ip
		uint32_t sender_IP = 0;
		struct sr_arphdr * arp_hdr =(struct sr_arphdr *)(packet + sizeof(struct sr_ethernet_hdr));
		struct sr_rt * rt_walker = sr->routing_table;

		//default next hop is 172.29.9.201
		sender_IP = rt_walker->gw.s_addr;

		while(rt_walker != NULL)
		{
			if(arp_hdr->ar_sip == rt_walker->dest.s_addr)
			{
				sender_IP = rt_walker->dest.s_addr;
				break;
			}
			rt_walker = rt_walker->next;
		}

		entry->ip_address = sender_IP;
		uint8_t* sender_MAC = (uint8_t* )malloc(sizeof(uint8_t) * 6);
		memcpy(sender_MAC, packet + 22, 6);
		memcpy(entry->mac_address_uint8_t, sender_MAC, 6);
		memcpy(entry->mac_address_unsigned_char, sender_MAC,  6);      
		entry->counter = 0;
		entry->interface_type = (char *)malloc(5);
		strncpy(entry->interface_type,interface, 5);
		entry->timestamp = time(0);	
		entry->next = NULL;
		
		free(sender_MAC);
		
		arp_cache_entry * arp_cache = arp_table;
		//if arp table is empty, adds one
		if(arp_cache->ip_address == 0)
		{
			arp_cache->ip_address = entry->ip_address;  
			memcpy(arp_cache->mac_address_uint8_t, entry->mac_address_uint8_t, 6);
			memcpy(arp_cache->mac_address_unsigned_char, entry->mac_address_unsigned_char, 6);
			arp_cache->interface_type = (char *)malloc(5);
			strncpy(arp_cache->interface_type, entry->interface_type, 5);
			arp_cache->counter = 0;
			arp_cache->next = NULL;
			return;
		}
		else
		{
			//check if already contain the entry
			arp_cache_entry * arp_pointer = arp_cache;
			while(arp_pointer != NULL)
			{
				if(arp_pointer->ip_address == entry->ip_address)
				{
					free(entry);
					return;
				}

				arp_pointer = arp_pointer->next;
			}

			//if is new entry
			arp_pointer = arp_cache;
			arp_cache_entry * arp_pointer_2 = arp_cache->next;
			while(arp_pointer_2 != NULL)
			{
				arp_pointer = arp_pointer->next;
				arp_pointer_2 = arp_pointer_2->next;
			}
			arp_pointer->next = entry;

		}
	}

	unsigned char* retrieve_mac_address(struct sr_instance* sr, char* interface)
	{
		struct sr_if* if_walker = 0;
		if(sr->if_list == 0)
		{
			printf("Interface list empty \n");
			return NULL;
		}
		if_walker = sr->if_list;

		unsigned char* mac = (unsigned char*)malloc(sizeof(unsigned char) * 6);

		while(if_walker)
		{
			if(!strncmp(if_walker->name, interface, 6))
			{
				memcpy(mac, if_walker->addr, 6);
			}
			if_walker= if_walker->next;
		}
		return mac;
	}


	uint8_t* retrieve_ip_address(struct sr_instance* sr, char* interface){
		struct sr_if* if_walker = 0;
		if(sr->if_list == 0)
		{
			printf("Interface list empty \n");
			return NULL;
		}
		if_walker = sr->if_list;

		uint8_t* ip = (uint8_t*)malloc(sizeof(uint8_t) * 4);

		while(if_walker)
		{
			if(!strncmp(if_walker->name, interface, 6))
			{
				*(ip) = if_walker->ip;
				*(ip + 1) = if_walker->ip>>8;
				*(ip + 2) = if_walker->ip>>16;
				*(ip + 3) = if_walker->ip>>24;
			}
			if_walker = if_walker->next;
		}
		return ip;
	}


