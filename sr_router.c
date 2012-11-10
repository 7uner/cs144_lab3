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
#include <stdlib.h>
#include <string.h>
#include <assert.h>


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





void convert_arp_hdr_to_host_byte_order (sr_arp_hdr_t *hdr)
{
  hdr->ar_hrd = ntohs (hdr->ar_hrd);
  hdr->ar_pro = ntohs (hdr->ar_pro);
  hdr->ar_op = ntohs (hdr->ar_op);
  /* sip and tip should be kept in network byte order to be consistent with 
     struct sr_if which keeps the ip field in network byte order */
}

void convert_arp_hdr_to_network_byte_order (sr_arp_hdr_t *hdr)
{
  hdr->ar_hrd = htons (hdr->ar_hrd);
  hdr->ar_pro = htons (hdr->ar_pro);
  hdr->ar_op = htons (hdr->ar_op);
  /* sip and tip should aleady be in network byte order */  
}

void convert_ethernet_hdr_to_network_byte_order (sr_ethernet_hdr_t *hdr)
{
  hdr->ether_type = htons (hdr->ether_type);
}

void handle_arp_request (struct sr_instance* sr, 
        sr_arp_hdr_t *req_arp_hdr, 
        char *interface)
{
  /* we can assume arp request is for us since vns_comm.c module has already 
     performed that check (see sr_arp_req_not_for_us function) */

  struct sr_if* iface = sr_get_interface(sr, interface);
  assert(iface);

  /* malloc space for reply packet */
  unsigned int reply_len = sizeof (sr_ethernet_hdr_t) + sizeof (sr_arp_hdr_t);
  uint8_t *reply_pkt = malloc (reply_len);
  sr_ethernet_hdr_t *reply_ethernet_hdr = (sr_ethernet_hdr_t *)reply_pkt;
  sr_arp_hdr_t *reply_arp_hdr = (sr_arp_hdr_t *)(reply_pkt + sizeof (sr_ethernet_hdr_t));

  /* fill out the ethernet header and convert to network byte order */
  memcpy (reply_ethernet_hdr->ether_dhost, req_arp_hdr->ar_sha, ETHER_ADDR_LEN);
  memcpy (reply_ethernet_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
  reply_ethernet_hdr->ether_type = ethertype_arp;
  convert_ethernet_hdr_to_network_byte_order (reply_ethernet_hdr);

  /* fill out the ARP header and convert to network byte order */
  reply_arp_hdr->ar_hrd = arp_hrd_ethernet;
  reply_arp_hdr->ar_pro = ethertype_ip;
  reply_arp_hdr->ar_hln = ETHER_ADDR_LEN;
  reply_arp_hdr->ar_pln = IP_ADDR_LEN;
  reply_arp_hdr->ar_op = arp_op_reply;
  memcpy (reply_arp_hdr->ar_sha, iface->addr, ETHER_ADDR_LEN);
  reply_arp_hdr->ar_sip = iface->ip;
  memcpy (reply_arp_hdr->ar_tha, req_arp_hdr->ar_sha, ETHER_ADDR_LEN);
  reply_arp_hdr->ar_tip = req_arp_hdr->ar_sip;
  convert_arp_hdr_to_network_byte_order (reply_arp_hdr);

  /* send ARP reply over the wire */
  sr_send_packet(sr, reply_pkt, reply_len, interface);
  free (reply_pkt);
}

void handle_arp_reply (uint8_t *packet)
{
    // TODO: implement
  printf("In handle_arp_reply: NOT IMPLEMENTED.\n");
}

void sr_handle_arp_packet (struct sr_instance* sr,
        uint8_t * packet,
        unsigned int len,
        char* interface)
{
  /* drop packet if it does not have the min length of an arp packet */
  if (len < sizeof (sr_ethernet_hdr_t) + sizeof (sr_arp_hdr_t))
    return;

  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof (sr_ethernet_hdr_t));

  convert_arp_hdr_to_host_byte_order (arp_hdr);

  /* drop packet if it is not for IP address resolution */
  if (arp_hdr->ar_pro != ethertype_ip)
  {
    fprintf (stderr, "Received an ARP packet to resolve an address that is not IP.\n");
    return;
  }

  if (arp_hdr->ar_op == arp_op_request)
    handle_arp_request (sr, arp_hdr, interface);
  else if (arp_hdr->ar_op == arp_op_reply) // TODO: continue
    handle_arp_reply (packet); 
  else
    fprintf (stderr, "Unknown arp op code %d. Dropping arp packet.\n", arp_hdr->ar_op);
}

void sr_handle_ip_packet (struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  // TODO: implement
  printf("In sr_handle_ip_packet: NOT IMPLEMENTED.\n");
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
  print_hdrs(packet, len);

  /* fill in code here */
  if (ethertype (packet) == ethertype_arp)
    sr_handle_arp_packet (sr, packet, len, interface);
  // TODO: continue
  // else if (ethertype (packet) == ethertype_ip)
  //   sr_handle_ip_packet (sr, packet, len, interface);
  // else
  //   fprintf(stderr, "Unknown ethertype: %d. Dropping packet.\n", ethertype (packet));

}/* end sr_ForwardPacket */

