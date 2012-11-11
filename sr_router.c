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

void convert_ip_hdr_to_host_byte_order (sr_ip_hdr_t *hdr)
{
  hdr->ip_len = ntohs (hdr->ip_len);
  // hdr->ip_id = ntohs (hdr->ip_id);
  // hdr->ip_off = ntohs (hdr->ip_off);
  hdr->ip_src = ntohl (hdr->ip_src);
  hdr->ip_dst = ntohl (hdr->ip_dst);
  fprintf(stderr, "in convert_ip_hdr_to_network_byte_order. NOT IMPLEMENTED.\n");
}

void convert_ethernet_hdr_to_network_byte_order (sr_ethernet_hdr_t *hdr)
{
  hdr->ether_type = htons (hdr->ether_type);
}

/* This function creates an arp packet for the given sha, sip, tha, tip and opcode. It returns
   a pointer to a raw ethernet frame containing the arp packet with all the appropariate fields in 
   network byte order. The packet returned is ready to be send over the wire. The caller MUST
   free the memory of this packet. */
uint8_t *create_arp_packet (uint8_t *sha, uint32_t sip, uint8_t *tha, uint32_t tip, unsigned short opcode)
{
  /* malloc space for ARP packet */
  unsigned int len = sizeof (sr_ethernet_hdr_t) + sizeof (sr_arp_hdr_t);
  uint8_t *pkt = malloc (len);
  sr_ethernet_hdr_t *ethernet_hdr = (sr_ethernet_hdr_t *)pkt;
  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(pkt + sizeof (sr_ethernet_hdr_t));

  /* fill out the ethernet header and convert to network byte order */
  memcpy (ethernet_hdr->ether_dhost, tha, ETHER_ADDR_LEN);
  memcpy (ethernet_hdr->ether_shost, sha, ETHER_ADDR_LEN);
  ethernet_hdr->ether_type = ethertype_arp;
  convert_ethernet_hdr_to_network_byte_order (ethernet_hdr);

  /* fill out the ARP header and convert to network byte order */
  arp_hdr->ar_hrd = arp_hrd_ethernet;
  arp_hdr->ar_pro = ethertype_ip;
  arp_hdr->ar_hln = ETHER_ADDR_LEN;
  arp_hdr->ar_pln = IP_ADDR_LEN;
  arp_hdr->ar_op = opcode;
  memcpy (arp_hdr->ar_sha, sha, ETHER_ADDR_LEN);
  arp_hdr->ar_sip = sip;
  memcpy (arp_hdr->ar_tha, tha, ETHER_ADDR_LEN);
  arp_hdr->ar_tip = tip;
  convert_arp_hdr_to_network_byte_order (arp_hdr);

  return pkt;
}

/* This function creates an arp reply for an arp requests and sends it
   over the wire */
void create_and_send_arp_reply (struct sr_instance *sr, 
        sr_arp_hdr_t *req_arp_hdr, 
        struct sr_if *iface)
{
  unsigned int reply_len = sizeof (sr_ethernet_hdr_t) + sizeof (sr_arp_hdr_t);
  uint8_t *reply_pkt = create_arp_packet (iface->addr, iface->ip, req_arp_hdr->ar_sha, req_arp_hdr->ar_sip, arp_op_reply);
  sr_send_packet (sr, reply_pkt, reply_len, iface->name);
  free (reply_pkt);
}

/* Sends a packet that was waiting on an arp reply. Just updates 
   the ethernet destination field with the arp reply data and sends */
void send_queued_packet (struct sr_instance *sr, 
                         struct sr_packet *packet, 
                         uint8_t *tha)
{
  unsigned int len = packet->len;
  sr_ethernet_hdr_t *ether_hdr = (sr_ethernet_hdr_t *)packet->buf;
  memcpy (&(ether_hdr->ether_dhost), tha, ETHER_ADDR_LEN);
  sr_send_packet (sr, packet->buf, len, packet->iface);
}

/* This function sends all packets that were waiting on an arp reply, if any, 
   removes them from the waiting queue, and frees all memory associated. */
void send_packets_waiting_on_reply (struct sr_instance *sr, 
                       sr_arp_hdr_t *arp_hdr, 
                       struct sr_if *iface, 
                       struct sr_arpreq *req)
{
  if (req)
  {
    for (struct sr_packet *pkt = req->packets; pkt != NULL; pkt = pkt->next)
      send_queued_packet (sr, pkt, arp_hdr->ar_sha);

    sr_arpreq_destroy(&(sr->cache), req);
  }
}

int sanity_check_arp_packet (sr_arp_hdr_t *arp_hdr, unsigned int len, int isBroadcast)
{
  int drop = 0;

  /* drop packet if it does not have the min length of an arp packet */
  if (len < sizeof (sr_arp_hdr_t))
  {
    fprintf (stderr, "Dropping arp packet. Too short. len: %d.\n", len);
    drop = 1;
  }
  if (arp_hdr->ar_op == arp_op_reply && isBroadcast)
  {
    fprintf(stderr, "Dropping arp packet. Ethernet broacast and an arp_reply.\n");
    drop = 1; /* reply should be unicast */
  }
  return drop;
}

/* This function takes in an arp packet (a ptr to the arp header) and processes it
   according to the algorithm in the "Packet reception" section of RFC826. i.e. 
   updates the ARP cache appropriately and in case of an ARP requests generates a 
   reply and in case of an ARP reply it sends all packets waiting on that reply. */
void sr_handle_arp_packet (struct sr_instance *sr,
        sr_arp_hdr_t *arp_hdr,
        unsigned int len,
        struct sr_if *iface, 
        int isBroadcast)
{
  convert_arp_hdr_to_host_byte_order (arp_hdr);

  int drop = sanity_check_arp_packet (arp_hdr, len, isBroadcast);

  if (drop)
    return;

  /* Steps 1 and 2 of RFC 826 packet reception algorithm: 
     drop packet if it is not for IP address resolution or if its not over ethernet */
  if (arp_hdr->ar_hrd != arp_hrd_ethernet || arp_hdr->ar_pro != ethertype_ip)
  {
    fprintf (stderr, "Received an ARP packet either non-ethernet or to resolve an address that is not IP.\n");
    return;
  }

  /* Step 3: if ARP cache contains an entry for the IP of sender update the cache */
  struct sr_arpreq *req;
  int updated = sr_arpcache_update(&(sr->cache), arp_hdr->ar_sha, arp_hdr->ar_sip, &req);

  /* Step 4: drop the packet if its not destined to us. */
  if (arp_hdr->ar_tip != iface->ip)
    return;

  /* Step 5: if cache didn't contain an entry for the sender's ip create one. */
  if (!updated)
    req = sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha, arp_hdr->ar_sip);

  /* Step 6: check op code and process accordingly; for a request send reply, 
     for a reply send packets waiting on the reply */
  if (arp_hdr->ar_op == arp_op_request)
    create_and_send_arp_reply (sr, arp_hdr, iface);
  else if (arp_hdr->ar_op == arp_op_reply)
    send_packets_waiting_on_reply (sr, arp_hdr, iface, req); 
  else
    fprintf (stderr, "Unknown arp op code %d. Dropping arp packet.\n", arp_hdr->ar_op);
}

int sanity_check_ip_packet (sr_ip_hdr_t *ip_hdr, unsigned int len)
{
  int drop = 0;

  /* drop packet if it does not have the min length of an arp packet */
  if (len < sizeof (sr_ip_hdr_t))
  {
    fprintf (stderr, "Dropping ip packet. Too short. len: %d.\n", len);
    drop = 1;
  }
  /* drop the packet if its IPv6 */
  if (ip_hdr->ip_v != 4)
  {
    fprintf (stderr, "Dropping ip packet. Version not supported. version = %d\n", ip_hdr->ip_v);
    drop = 1;
  }
  /* drop the packet if the header checksum verification fails */
  uint16_t chksum = ip_hdr->ip_sum;
  ip_hdr->ip_sum = 0;
  if (cksum ((void *)ip_hdr, sizeof(sr_ip_hdr_t)) != chksum)
  {
    fprintf (stderr, "Dropping ip packet. Corrupted checksum. %d vs %d\n", cksum ((void *)ip_hdr, IP_ADDR_LEN), chksum);
    drop = 1;
  }

  return drop;
}

void sr_handle_ip_packet (struct sr_instance *sr,
        uint8_t *packet,
        unsigned int len,
        struct sr_if *iface)
{
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)packet;
  
  int drop = sanity_check_ip_packet (ip_hdr, len);

  if (drop)
    return;

  convert_ip_hdr_to_host_byte_order (ip_hdr);


  // TODO: implement
  fprintf (stderr, "In sr_handle_ip_packet: NOT IMPLEMENTED.\n");
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

  fprintf (stderr, "*** -> Received packet of length %d \n",len);
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
      fprintf (stderr, "Dropping arp packet. Destination eth_addr: %s not recognized.\n", ether_hdr->ether_dhost);
      return;
    }
    sr_handle_arp_packet (sr, (sr_arp_hdr_t *)(packet + sizeof (sr_ethernet_hdr_t)), 
                          len - sizeof (sr_ethernet_hdr_t), iface, isBroadcast);
  }
  else if (ethertype (packet) == ethertype_ip)
  {
    /* drop packet if it's not destined to us */
    if (!eth_addr_equals (ether_hdr->ether_dhost, iface->addr))
      return;
    sr_handle_ip_packet (sr, packet + sizeof (sr_ethernet_hdr_t),
                         len - sizeof (sr_ethernet_hdr_t), iface);
  }
  else
    fprintf(stderr, "Unknown ethertype: %d. Dropping packet.\n", ethertype (packet));

  sr_arpcache_print_cache (&(sr->cache));
}/* end sr_ForwardPacket */

