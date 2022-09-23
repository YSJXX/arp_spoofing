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
      for (int i = 0; i < 6; i++)
            if (mac1[i] != mac2[i])
                  return 0;
      return 1;
}

void insertPacketField(u_int8_t *pkt, char *argv[], u_int8_t type)
{
      struct eth_arp_header *send_packet = (struct eth_arp_header *)pkt;

      for (int i = 0; i <= 5; i++)
            send_packet->eth_dst_mac[i] = 0xFF;

      for (int i = 0; i <= 5; i++)
            send_packet->eth_src_mac[i] = mymac[i];

      send_packet->type = ntohs(0x0806);
      send_packet->hd_type = ntohs(0x0001);
      send_packet->protocol_type = ntohs(0x0800);
      send_packet->hd_size = 0x06;
      send_packet->protocol_size = 0x04;
      send_packet->opcode = ntohs(0x0001);

      for (int i = 0; i <= 5; i++)
            send_packet->arp_sender_mac[i] = mymac[i];

      send_packet->arp_sender_ip = type == TARGET ? inet_addr(argv[3]) : inet_addr(myip);

      for (int i = 0; i <= 5; i++)
            send_packet->arp_target_mac[i] = 0x00;

      send_packet->arp_target_ip = type == TARGET ? inet_addr(argv[2]) : inet_addr(argv[3]);
}