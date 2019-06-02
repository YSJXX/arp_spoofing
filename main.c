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



int main(int argc, char* argv[]) {

      if (argc <= 2 || argc%2 == 1) {
         printf("error\n");
         return -1;
       }

      char* dev = argv[1];
      char errbuf[PCAP_ERRBUF_SIZE];
      pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
      if (handle == NULL) {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
      }

      argcs = argc;
      for(int i=1;i<=argc/2-1;i++)
      {
        broadcast(argv,handle);       //최초 감염 시작. for문 다 돌기전에 reply 패킷 오는지 확인 해야함.
      }


      while(1)
      {
        process(argv,handle);

      }

      pcap_close(handle);
      return 0;
}

