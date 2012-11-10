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
    assert (sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init (&(sr->cache));

    pthread_attr_init (&(sr->attr));
    pthread_attr_setdetachstate (&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope (&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope (&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create (&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
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

void handle_arp_request (struct sr_instance *sr, 
        sr_arp_hdr_t *req_arp_hdr, 
        struct sr_if *iface)
{
  /* we can assume arp request is for us (our ip) since vns_comm.c module has already 
     performed that check (see sr_arp_req_not_for_us function) */

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
  sr_send_packet (sr, reply_pkt, reply_len, iface->name);
  free (reply_pkt);
}

void send_queued_packet (struct sr_instance *sr, 
                         struct sr_packet *packet, 
                         uint8_t *tha)
{
  unsigned int len = packet->len;
  sr_ethernet_hdr_t *ether_hdr = (sr_ethernet_hdr_t *)packet->buf;
  memcpy (&(ether_hdr->ether_dhost), tha, ETHER_ADDR_LEN);
  sr_send_packet (sr, packet->buf, len, packet->iface);
}

void handle_arp_reply (struct sr_instance *sr, 
                       sr_arp_hdr_t *arp_hdr, 
                       struct sr_if *iface)
{
  if (arp_hdr->ar_tip != iface->ip)
    return;

  struct sr_arpreq *req = sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha, arp_hdr->ar_sip);

  if (req)
  {
    for (struct sr_packet *pkt = req->packets; pkt != NULL; pkt = pkt->next)
      send_queued_packet (sr, pkt, arp_hdr->ar_sha);

    sr_arpreq_destroy(&(sr->cache), req);
  }
}

void sr_handle_arp_packet (struct sr_instance *sr,
        sr_arp_hdr_t *arp_hdr,
        unsigned int len,
        struct sr_if *iface, 
        int isBroadcast)
{
  /* drop packet if it does not have the min length of an arp packet */
  if (len < sizeof (sr_arp_hdr_t))
  {
    fprintf (stderr, "Dropping arp packet. Too short. len: %d.\n", len);
    return;
  }

  convert_arp_hdr_to_host_byte_order (arp_hdr);

  /* drop packet if it is not for IP address resolution or if its not over ethernet */
  if (arp_hdr->ar_hrd != arp_hrd_ethernet || arp_hdr->ar_pro != ethertype_ip)
  {
    fprintf (stderr, "Received an ARP packet either non-ethernet or to resolve an address that is not IP.\n");
    return;
  }

  if (arp_hdr->ar_op == arp_op_request)
    handle_arp_request (sr, arp_hdr, iface);
  else if (arp_hdr->ar_op == arp_op_reply)
  {
    if (isBroadcast) /* reply should be unicast */
      return;
    handle_arp_reply (sr, arp_hdr, iface); 
  }
  else
    fprintf (stderr, "Unknown arp op code %d. Dropping arp packet.\n", arp_hdr->ar_op);
}

void sr_handle_ip_packet (struct sr_instance *sr,
        uint8_t *packet,
        unsigned int len,
        struct sr_if *iface)
{
  // TODO: implement
  printf ("In sr_handle_ip_packet: NOT IMPLEMENTED.\n");
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

void sr_handlepacket(struct sr_instance *sr,
        uint8_t *packet/* lent */,
        unsigned int len,
        char *interface/* lent */)
{
  /* REQUIRES */
  assert (sr);
  assert (packet);
  assert (interface);

  printf ("*** -> Received packet of length %d \n",len);
  print_hdrs (packet, len);

  /* fill in code here */
  struct sr_if *iface = sr_get_interface(sr, interface);
  assert (iface);
  sr_ethernet_hdr_t *ether_hdr = (sr_ethernet_hdr_t *)packet;

  /* drop if packet is too short */
  if (len < sizeof (sr_ethernet_hdr_t))
  {
    fprintf (stderr, "Dropping ethernet frame. Too short. len: %d.\n", len);
    return;
  }

  if (ethertype (packet) == ethertype_arp)
  {
    ethernet_addr_t broadcast_addr = mac_string_to_bytes ("ff:ff:ff:ff:ff:ff");
    int isBroadcast = eth_addr_equals (ether_hdr->ether_dhost, (uint8_t *)&broadcast_addr);

    /* drop the packet if it is not destined to our MAC address or its
     not a broadcast */
    if (!isBroadcast && !eth_addr_equals (ether_hdr->ether_dhost, iface->addr))
    { 
      printf ("Dropping arp packet. Destination eth_addr: %s not recognized.\n", ether_hdr->ether_dhost);
      return;
    }
    sr_handle_arp_packet (sr, (sr_arp_hdr_t *)(packet + sizeof (sr_ethernet_hdr_t)), 
                          len - sizeof (sr_ethernet_hdr_t), iface, isBroadcast);
  }
  // // TODO: continue
  // else if (ethertype (packet) == ethertype_ip)
  // {
  //   /* drop packet if it's not destined to us */
  //   if (!eth_addr_equals (ether_hdr->ether_dhost, iface->addr))
  //     return;
  //   sr_handle_ip_packet (sr, packet, len, iface);
  // }
  else
    fprintf(stderr, "Unknown ethertype: %d. Dropping packet.\n", ethertype (packet));
}/* end sr_ForwardPacket */

