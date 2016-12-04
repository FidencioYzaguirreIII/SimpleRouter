/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
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

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_send_arpreply(struct sr_instance *sr, uint8_t *orig_pkt,
 *             unsigned int orig_len, struct sr_if *src_iface)
 * Scope:  Local
 *
 * Send an ARP reply packet in response to an ARP request for one of
 * the router's interfaces 
 *---------------------------------------------------------------------*/
void sr_send_arpreply(struct sr_instance *sr, uint8_t *orig_pkt,
    unsigned int orig_len, struct sr_if *src_iface)
{
  /* Allocate space for packet */
  unsigned int reply_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
  uint8_t *reply_pkt = (uint8_t *)malloc(reply_len);
  if (NULL == reply_pkt)
  {
    fprintf(stderr,"Failed to allocate space for ARP reply");
    return;
  }

  sr_ethernet_hdr_t *orig_ethhdr = (sr_ethernet_hdr_t *)orig_pkt;
  sr_arp_hdr_t *orig_arphdr = 
      (sr_arp_hdr_t *)(orig_pkt + sizeof(sr_ethernet_hdr_t));

  sr_ethernet_hdr_t *reply_ethhdr = (sr_ethernet_hdr_t *)reply_pkt;
  sr_arp_hdr_t *reply_arphdr = 
      (sr_arp_hdr_t *)(reply_pkt + sizeof(sr_ethernet_hdr_t));

  /* Populate Ethernet header */
  memcpy(reply_ethhdr->ether_dhost, orig_ethhdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(reply_ethhdr->ether_shost, src_iface->addr, ETHER_ADDR_LEN);
  reply_ethhdr->ether_type = orig_ethhdr->ether_type;

  /* Populate ARP header */
  memcpy(reply_arphdr, orig_arphdr, sizeof(sr_arp_hdr_t));
  reply_arphdr->ar_hrd = orig_arphdr->ar_hrd;
  reply_arphdr->ar_pro = orig_arphdr->ar_pro;
  reply_arphdr->ar_hln = orig_arphdr->ar_hln;
  reply_arphdr->ar_pln = orig_arphdr->ar_pln;
  reply_arphdr->ar_op = htons(arp_op_reply); 
  memcpy(reply_arphdr->ar_tha, orig_arphdr->ar_sha, ETHER_ADDR_LEN);
  reply_arphdr->ar_tip = orig_arphdr->ar_sip;
  memcpy(reply_arphdr->ar_sha, src_iface->addr, ETHER_ADDR_LEN);
  reply_arphdr->ar_sip = src_iface->ip;

  /* Send ARP reply */
  printf("Send ARP reply\n");
  print_hdrs(reply_pkt, reply_len);
  sr_send_packet(sr, reply_pkt, reply_len, src_iface->name);
  free(reply_pkt);
} /* -- sr_send_arpreply -- */

/*---------------------------------------------------------------------
 * Method: sr_send_arprequest(struct sr_instance *sr, 
 *             struct sr_arpreq *req,i struct sr_if *out_iface)
 * Scope:  Local
 *
 * Send an ARP reply packet in response to an ARP request for one of
 * the router's interfaces 
 *---------------------------------------------------------------------*/
void sr_send_arprequest(struct sr_instance *sr, struct sr_arpreq *req,
    struct sr_if *out_iface)
{
  /* Allocate space for ARP request packet */
  unsigned int reqst_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
  uint8_t *reqst_pkt = (uint8_t *)malloc(reqst_len);
  if (NULL == reqst_pkt)
  {
    fprintf(stderr,"Failed to allocate space for ARP reply");
    return;
  }

  sr_ethernet_hdr_t *reqst_ethhdr = (sr_ethernet_hdr_t *)reqst_pkt;
  sr_arp_hdr_t *reqst_arphdr = 
      (sr_arp_hdr_t *)(reqst_pkt + sizeof(sr_ethernet_hdr_t));

  /* Populate Ethernet header */
  memset(reqst_ethhdr->ether_dhost, 0xFF, ETHER_ADDR_LEN);
  memcpy(reqst_ethhdr->ether_shost, out_iface->addr, ETHER_ADDR_LEN);
  reqst_ethhdr->ether_type = htons(ethertype_arp);

  /* Populate ARP header */
  reqst_arphdr->ar_hrd = htons(arp_hrd_ethernet);
  reqst_arphdr->ar_pro = htons(ethertype_ip);
  reqst_arphdr->ar_hln = ETHER_ADDR_LEN;
  reqst_arphdr->ar_pln = sizeof(uint32_t);
  reqst_arphdr->ar_op = htons(arp_op_request); 
  memcpy(reqst_arphdr->ar_sha, out_iface->addr, ETHER_ADDR_LEN);
  reqst_arphdr->ar_sip = out_iface->ip;
  memset(reqst_arphdr->ar_tha, 0x00, ETHER_ADDR_LEN);
  reqst_arphdr->ar_tip = req->ip;

  /* Send ARP request */
  printf("Send ARP request\n");
  print_hdrs(reqst_pkt, reqst_len);
  sr_send_packet(sr, reqst_pkt, reqst_len, out_iface->name);
  free(reqst_pkt);
} /* -- sr_send_arprequest -- */

/*---------------------------------------------------------------------
 * Method: sr_handle_arpreq(struct sr_instance *sr, 
 *             struct sr_arpreq *req, struct sr_if *out_iface)
 * Scope:  Global
 *
 * Perform processing for a pending ARP request: do nothing, timeout, or  
 * or generate an ARP request packet 
 *---------------------------------------------------------------------*/
void sr_handle_arpreq(struct sr_instance *sr, struct sr_arpreq *req,
    struct sr_if *out_iface)
{
  time_t now = time(NULL);
  if (difftime(now, req->sent) >= 1.0)
  {
    if (req->times_sent >= 5)
    {
      /*********************************************************************/
      /* TODO: send ICMP host uncreachable to the source address of all    */
      /* packets waiting on this request                                   */

          /*Set up the reply frame*/
          unsigned int replyLen = (sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
	  uint8_t* replyFrame = malloc(replyLen);
	  sr_ethernet_hdr_t* ethernetReply = (sr_ethernet_hdr_t *)replyFrame;
      	  sr_ip_hdr_t* ipReply = (sr_ip_hdr_t*) (replyFrame+sizeof(sr_ethernet_hdr_t));
	  sr_icmp_t3_hdr_t* icmpReply = (sr_icmp_t3_hdr_t*) (ipReply+sizeof(sr_ip_hdr_t)) ;
	  struct  sr_packet* pkt = req->packets;
	  while (pkt != NULL) /*While loop is active as long as their are packets to send*/
	  {
		sr_ip_hdr_t* ipPkt = (sr_ip_hdr_t*) (pkt + sizeof(sr_ethernet_hdr_t));
		
		struct sr_rt* tableMatch  = longestPrefixMatch(sr,ipPkt->ip_src); /*Use longest prefix match to find routing info on ip address*/
		if (!tableMatch){
			return;
		}
	
		struct sr_if* neededInterface = sr_get_interface(sr,tableMatch->interface); /*Get interface of routing table*/
		if(!neededInterface){
			return;
		}

		/* Fill out Ethernet Header*/
		memcpy(ethernetReply->ether_shost, neededInterface->addr, ETHER_ADDR_LEN);
		ethernetReply-> ether_type = ethertype_ip;
		
		/* Fill out IP Header*/
		ipReply->ip_v = 4;
		ipReply->ip_hl = ipPkt->ip_hl;
		ipReply->ip_tos = 0;
		ipReply->ip_len = htons(sizeof(ipReply) + sizeof(icmpReply));
		ipReply->ip_id = ipPkt->ip_id; /* No fragmentaion so ne need to worry */
;	    	ipReply->ip_off = htons(IP_DF);
	    	ipReply->ip_ttl = 64; /* If things are timeing out to much increase*/
	    	ipReply->ip_p = 17;
	    	ipReply->ip_sum = 0;
		ipReply->ip_src = out_iface->ip;
		ipReply->ip_dst = ipPkt->ip_src;
		ipReply->ip_sum = cksum(ipReply, ipReply->ip_len);

		/* Fill out ICMP Header*/
		icmpReply->icmp_type = 3;
		icmpReply->icmp_code = 1;
		icmpReply->icmp_sum = 0;
		memcpy(icmpReply->data, ipPkt, ICMP_DATA_SIZE);
		icmpReply->icmp_sum = cksum(icmpReply, sizeof(sr_icmp_t3_hdr_t));

		/*Print headers, send packet, free memory, and go to next packet*/
		print_hdrs(replyFrame, replyLen);
		sr_attempt_send(sr,tableMatch->gw.s_addr,replyFrame,replyLen,neededInterface);
		free(replyFrame);
		pkt = pkt->next;
	  }

      /*********************************************************************/

      sr_arpreq_destroy(&(sr->cache), req);
    }
    else
    { 
      /* Send ARP request packet */
      sr_send_arprequest(sr, req, out_iface);
       
      /* Update ARP request entry to indicate ARP request packet was sent */ 
      req->sent = now;
      req->times_sent++;
    }
  }
} /* -- sr_handle_arpreq -- */

/*---------------------------------------------------------------------
 * Method: void sr_waitforarp(struct sr_instance *sr, uint8_t *pkt,
 *             unsigned int len, uint32_t next_hop_ip, 
 *             struct sr_if *out_iface)
 * Scope:  Local
 *
 * Queue a packet to wait for an entry to be added to the ARP cache
 *---------------------------------------------------------------------*/
void sr_waitforarp(struct sr_instance *sr, uint8_t *pkt,
    unsigned int len, uint32_t next_hop_ip, struct sr_if *out_iface)
{
    struct sr_arpreq *req = sr_arpcache_queuereq(&(sr->cache), next_hop_ip, 
            pkt, len, out_iface->name);
    sr_handle_arpreq(sr, req, out_iface);
} /* -- sr_waitforarp -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket_arp(struct sr_instance *sr, uint8_t *pkt,
 *             unsigned int len, struct sr_if *src_iface)
 * Scope:  Local
 *
 * Handle an ARP packet that was received by the router
 *---------------------------------------------------------------------*/
void sr_handlepacket_arp(struct sr_instance *sr, uint8_t *pkt,
    unsigned int len, struct sr_if *src_iface)
{
  /* Drop packet if it is less than the size of Ethernet and ARP headers */
  if (len < (sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)))
  {
    printf("Packet is too short => drop packet\n");
    return;
  }

  sr_arp_hdr_t *arphdr = (sr_arp_hdr_t *)(pkt + sizeof(sr_ethernet_hdr_t));

  switch (ntohs(arphdr->ar_op))
  {
  case arp_op_request:
  {
    /* Check if request is for one of my interfaces */
    if (arphdr->ar_tip == src_iface->ip)
    { sr_send_arpreply(sr, pkt, len, src_iface); }
    break;
  }
  case arp_op_reply:
  {
    /* Check if reply is for one of my interfaces */
    if (arphdr->ar_tip != src_iface->ip)
    { break; }

    /* Update ARP cache with contents of ARP reply */
    struct sr_arpreq *req = sr_arpcache_insert(&(sr->cache), arphdr->ar_sha, 
        arphdr->ar_sip);

    /* Process pending ARP request entry, if there is one */
    if (req != NULL)
    {
      /*********************************************************************/
      /* TODO: send all packets on the req->packets linked list            */
      while (req->packets != NULL) /*Keep active for all packets*/
		{
		        struct sr_packet* pkt = req->packets;
	   	        memcpy(((sr_ethernet_hdr_t*)pkt->buf)->ether_dhost, arphdr->ar_sha, ETHER_ADDR_LEN);/*Copy address into packet*/
			sr_send_packet(sr, pkt->buf, pkt->len, pkt->iface); /*Send pkt*/
			req->packets = req->packets->next;
			free(pkt->buf); /*Free memory*/
			free(pkt->iface);
			free(pkt);
		}

      /*********************************************************************/

      /* Release ARP request entry */
      sr_arpreq_destroy(&(sr->cache), req);
    }
    break;
  }    
  default:
    printf("Unknown ARP opcode => drop packet\n");
    return;
  }
} /* -- sr_handlepacket_arp -- */


void sr_handlepacket_ip(struct sr_instance *sr, uint8_t *pkt, /*Handles the ip packets*/
    unsigned int len, struct sr_if *src_iface){
    if(len < (sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t))){ /*Check to see if we need to drop packet*/
	printf("Packet is too short => drop packet\n");
	return;
    }
    
    sr_ip_hdr_t* iphdr = (sr_ip_hdr_t*)(pkt+sizeof(sr_ethernet_hdr_t));
    
    /*Use checksum to see if pack needs to drop*/
    int sum = iphdr->ip_sum;
    iphdr->ip_sum = 0;
    uint16_t checksum = cksum(iphdr,iphdr->ip_hl*4);
    iphdr->ip_sum = sum;
    if(checksum != sum){
	printf("Checksum does not match sum given. Packet will be dropped");
	return;
    }
    

    struct sr_if* node = sr->if_list;/*Check to see if packet is at destiantion*/
    while(node != NULL){
      
      if(node->ip == iphdr->ip_dst){
	break;
      }
      node = node->next;
    }

    if(node){	/*If so go to loop*/
        uint32_t ipSource  = iphdr->ip_src;
        struct  sr_rt* tableMatch = longestPrefixMatch(sr,ipSource);  /*Use longest prefix match to find routing info on ip address*/
	if (!tableMatch){
		return;
	}

	struct sr_if* neededInterface = sr_get_interface(sr,tableMatch->interface); /*Retrieve interface of routing table*/
	if(!neededInterface){
		return;
	}

	unsigned int replyLen = 0;

	if(iphdr->ip_p == ip_protocol_icmp){  /*Check to see if we have an error*/
	        replyLen = (sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t));
	}
	else{
	        replyLen = (sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
	}

	/*set up frame*/
    	uint8_t* replyFrame = malloc(replyLen);
	sr_ethernet_hdr_t* ethernetReply = (sr_ethernet_hdr_t *)replyFrame;
    	sr_ip_hdr_t* ipReply = (sr_ip_hdr_t*) (replyFrame+sizeof(sr_ethernet_hdr_t));

	if(iphdr->ip_p == ip_protocol_icmp){ /*Ping icmp*/
    		sr_icmp_hdr_t* icmpReply = (sr_icmp_hdr_t*) (ipReply+sizeof(sr_ip_hdr_t));
		/* Fill out ICMP Header*/
                ipReply->ip_len = htons(sizeof(ipReply) + sizeof(icmpReply));
		icmpReply->icmp_type = 0;
		icmpReply->icmp_code = 0;
		icmpReply->icmp_sum = 0;
        	icmpReply->icmp_sum = cksum(icmpReply, sizeof(sr_icmp_hdr_t));
	}
	else{ /*Error ICMP*/
		sr_icmp_t3_hdr_t* icmpReply = (sr_icmp_t3_hdr_t*) (ipReply+sizeof(sr_ip_hdr_t));
		/* Fill out ICMP Header*/
                ipReply->ip_len = htons(sizeof(ipReply) + sizeof(icmpReply));
		icmpReply->icmp_type = 3;
		icmpReply->icmp_code = 3;
		icmpReply->icmp_sum = 0;
		memcpy(icmpReply->data, iphdr, ICMP_DATA_SIZE);
		icmpReply->icmp_sum = cksum(icmpReply, sizeof(sr_icmp_t3_hdr_t));
	}

	/*Fill out ethernet header*/ 
	memcpy(ethernetReply->ether_shost, neededInterface->addr , ETHER_ADDR_LEN);
	ethernetReply-> ether_type = ethertype_ip;

       	/* Fill out IP Header*/
	ipReply->ip_v = 4;
	ipReply->ip_hl = iphdr->ip_hl;
	ipReply->ip_tos = 0;
       	ipReply->ip_id = iphdr->ip_id; /* No fragmentaion so ne need to worry*/
	ipReply->ip_off = htons(IP_DF);
       	ipReply->ip_ttl = 64;  /* If things are timeing out to much increase*/
	ipReply->ip_p = ip_protocol_icmp;
	ipReply->ip_sum = 0;
	ipReply->ip_src = iphdr->ip_dst;
	ipReply->ip_dst = iphdr->ip_src;
	ipReply->ip_sum = cksum(ipReply, ipReply->ip_len);
	
	/*Print headers and send packet*/
	print_hdrs(replyFrame, replyLen);
	sr_attempt_send(sr,tableMatch->gw.s_addr,replyFrame,replyLen,neededInterface);
	free(replyFrame); /*free memory*/
	return;
    }
    
    uint8_t nextTtl = iphdr->ip_ttl-1;
    if(nextTtl == 1){ /*Check to see if packet needs to die*/
      /*Make reply frame*/
        unsigned int replyLen = (sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t));
    	uint8_t* replyFrame = malloc(replyLen);
    	sr_ethernet_hdr_t* ethernetReply = (sr_ethernet_hdr_t *)replyFrame;
    	sr_ip_hdr_t* ipReply = (sr_ip_hdr_t*) (replyFrame+sizeof(sr_ethernet_hdr_t));
    	sr_icmp_hdr_t* icmpReply = (sr_icmp_hdr_t*) (ipReply+sizeof(sr_ip_hdr_t));
	
	struct sr_rt* tableMatch  = longestPrefixMatch(sr,iphdr->ip_src);  /*Use longest prefix match to find routing info on ip address*/
	if (!tableMatch){
		return;
	}

	struct sr_if* neededInterface = sr_get_interface(sr,tableMatch->interface);/*Get routing interface from routing table*/
	if(!neededInterface){
		return;
	}

	/*Fill out ethernet header*/
	memcpy(ethernetReply->ether_shost, neededInterface->addr , ETHER_ADDR_LEN);
	ethernetReply-> ether_type = ethertype_ip;

        /* Fill out IP Header*/
	ipReply->ip_v = 4;
	ipReply->ip_hl = iphdr->ip_hl;
	ipReply->ip_tos = 0;
	ipReply->ip_len = htons(sizeof(ipReply) + sizeof(icmpReply));
        ipReply->ip_id = iphdr->ip_id; /* No fragmentaion so ne need to worry*/
	ipReply->ip_off = htons(IP_DF);
        ipReply->ip_ttl = 64; /* If things are timeing out to much increase*/
	ipReply->ip_p = ip_protocol_icmp;
	ipReply->ip_sum = 0;
	ipReply->ip_src = iphdr->ip_dst;
	ipReply->ip_dst = iphdr->ip_src;
	ipReply->ip_sum = cksum(ipReply, ipReply->ip_len);

        /* Fill out ICMP Header*/
	icmpReply->icmp_type = 11;
	icmpReply->icmp_code = 0;
	icmpReply->icmp_sum = 0;
        icmpReply->icmp_sum = cksum(icmpReply, sizeof(sr_icmp_hdr_t));
	
	/*Print headers and send packet*/
	print_hdrs(replyFrame, replyLen);
	sr_attempt_send(sr,tableMatch->gw.s_addr,replyFrame,replyLen,neededInterface);
	free(replyFrame);
    }
       
       /* This is where the ttl decreasement was supose to happpend but for some reason it would send the packet of never to be heard from again.
       iphdr->ip_ttl = nextTtl;
       iphdr->ip_sum = 0;
       iphdr->ip_sum = cksum(iphdr,iphdr->ip_len);*/

    struct sr_rt* tableMatch = longestPrefixMatch(sr,iphdr->ip_dst); /*Use longest prefix match to find routing info on ip address*/
    
    if(tableMatch){ /*If IP is in routing table*/
       /*Set up frame*/
        unsigned int replyLen = (sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t));
    	uint8_t* replyFrame = malloc(len);	
	memcpy(replyFrame,pkt,len);
        
	/*Insert ethernet source host*/
	sr_ethernet_hdr_t* ethernetFrame = (sr_ethernet_hdr_t*)replyFrame;
	struct sr_if* neededInterface = sr_get_interface(sr,tableMatch->interface);
	memcpy(ethernetFrame->ether_shost,neededInterface->addr,ETHER_ADDR_LEN);

	/*Print headers,send packet, and free memory*/
    	print_hdrs(replyFrame, replyLen);
	sr_attempt_send(sr,tableMatch->gw.s_addr,replyFrame,len,neededInterface);
	free(replyFrame);
    }
    else{
      /*Set up frame*/
        unsigned int replyLen = (sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
    	uint8_t* replyFrame = malloc(replyLen);
    	sr_ethernet_hdr_t* ethernetReply = (sr_ethernet_hdr_t *)replyFrame;
    	sr_ip_hdr_t* ipReply = (sr_ip_hdr_t*) (replyFrame+sizeof(sr_ethernet_hdr_t));
    	sr_icmp_t3_hdr_t* icmpReply = (sr_icmp_t3_hdr_t*) (ipReply+sizeof(sr_ip_hdr_t));
	
	struct sr_rt* tableMatch = longestPrefixMatch(sr,iphdr->ip_src);  /*Use longest prefix match to find routing info on ip address*/
	if (!tableMatch){
		return;
	}

	struct sr_if* neededInterface = sr_get_interface(sr,tableMatch->interface); /*Retrive interface of routing table*/
	if(!neededInterface){
		return;
	}
	

	/*Fill out Ethernet Header*/
	memcpy(ethernetReply->ether_shost, neededInterface->addr , ETHER_ADDR_LEN);
	ethernetReply-> ether_type = ethertype_ip;

        /* Fill out IP Header*/
	ipReply->ip_v = 4;
	ipReply->ip_hl = iphdr->ip_hl;
	ipReply->ip_tos = 0;
	ipReply->ip_len = htons(sizeof(ipReply) + sizeof(icmpReply));
        ipReply->ip_id = iphdr->ip_id; /* No fragmentaion so ne need to worry*/
	ipReply->ip_off = htons(IP_DF);
        ipReply->ip_ttl = iphdr->ip_ttl-1; /* If things are timeing out to much increase*/
	ipReply->ip_p = ip_protocol_icmp;
	ipReply->ip_sum = 0;
	ipReply->ip_src = src_iface->ip;
	ipReply->ip_dst = iphdr->ip_src;
	ipReply->ip_sum = cksum(ipReply, ipReply->ip_len);

        /* Fill out ICMP Header*/
	icmpReply->icmp_type = 3;
	icmpReply->icmp_code = 0;
	icmpReply->icmp_sum = 0;
        memcpy(icmpReply->data, iphdr, ICMP_DATA_SIZE);
	icmpReply->icmp_sum = cksum(icmpReply, sizeof(sr_icmp_t3_hdr_t));
	
	/*Print headers free memory and send packet*/
	print_hdrs(replyFrame, replyLen);
	sr_attempt_send(sr,tableMatch->gw.s_addr,replyFrame,replyLen,neededInterface);
	free(replyFrame);
    }
}



/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
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
 
  printf("*** -> Received packet of length %d \n",len);

  /*************************************************************************/
  /* TODO: Handle packets */
  int totalLength = sizeof(sr_ethernet_hdr_t);                                                 
  if(len<totalLength){
	return;
  }
  
  uint16_t ethernetType = ethertype(packet);
  struct  sr_if* interfaceEntry = sr_get_interface(sr,interface);
  if(ethernetType == ethertype_arp){   /*Check erthernet type to determine action*/
        sr_handlepacket_arp(sr,packet,len,interfaceEntry); /*Handle arp packet*/
  }
  else{ /*Handle Ip packet*/
	sr_handlepacket_ip(sr,packet,len,interfaceEntry);
  }

  /*************************************************************************/

}
/* end sr_ForwardPacket */

/*Check arp cache for hardware address*/
void sr_attempt_send(struct sr_instance *sr, uint32_t ip_dest, uint8_t *pkt,unsigned int len, struct sr_if *out_iface){

  struct sr_arpentry *entry = sr_arpcache_lookup(&(sr->cache), ip_dest); /*Look tin arp cache for hardware address of ip router*/

   if (entry){

        unsigned char *mac_address = entry->mac; 
        memcpy( ((sr_ethernet_hdr_t *)pkt)->ether_dhost, mac_address, ETHER_ADDR_LEN); /*Copy Mac address into ethernet header*/
        sr_send_packet(sr, pkt, len, out_iface->name); /*Send the packet*/

        free(entry); /*Free memory*/


   }else{
        fprintf(stderr, "Couldn't find entry for: ");
        print_addr_ip_int(ntohl(ip_dest));

	sr_waitforarp(sr, pkt,len, ip_dest,  out_iface); /*Time to handle some arp requests*/
   }
}
