
    #include <pcap.h>
    #include <stdio.h>
    #include <arpa/inet.h>
    #include "ip_header.h"

    int main()
    {
       pcap_t *handle;         /* Session handle */
       char *dev;         /* The device to sniff on */
       char errbuf[PCAP_ERRBUF_SIZE];   /* Error string */
       struct bpf_program fp;      /* The compiled filter */
       char filter_exp[] = "port 80";   /* The filter expression */
       bpf_u_int32 mask;      /* Our netmask */
       bpf_u_int32 net;      /* Our IP */
       struct MEC_Ether_header *  pEth;    // 이더넷 헤더 *
       // struct MEC_Ip_header *    pIph;    // IP헤더 *
        struct libnet_ipv4_hdr * pIph;
        struct libnet_tcp_hdr * pTph;

       /* Define the device */
       dev = pcap_lookupdev(errbuf);
       if (dev == NULL) {
           fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
           return(2);
       }
       /* Find the properties for the device */
       if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
           fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
           net = 0;
           mask = 0;
       }
       /* Open the session in promiscuous mode */
       handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
       if (handle == NULL) {
           fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
           return(2);
       }
       /* Compile and apply the filter */
       if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
           fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
           return(2);
       }
       if (pcap_setfilter(handle, &fp) == -1) {
           fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
           return(2);
       }
       /* Grab a packet */
       while(1){
           struct pcap_pkthdr * hdr;
           const u_char * packet;
           const int res = pcap_next_ex(handle, &hdr, &packet);
           if(res<0)
               break;
           if(res==0)
               continue;

          pEth = (struct MEC_Ether_header *)packet; // (Eth 헤더 구조체)
          pIph = (struct libnet_ipv4_hdr*)(packet + sizeof(*pEth));  //  (Ip 헤더 구조체)
          pTph = (struct libnet_tcp_hdr *)(packet + sizeof(*pEth)+sizeof(*pIph)); // (TCP 헤더 구조체)

          /* Eth 헤더 출력부 시작 */
                printf("================================================================\n");

                fprintf(stdout, "DESTINATION Physical Address - [");        // 도착지 Eth주소 출력
                for(int iCnt = 0 ; iCnt < 6 ; ++iCnt)
                 {
                   fprintf(stdout, "%02X:", pEth->ether_dhost[iCnt]);
                 }
                 fprintf(stdout, "\b]\t\t\n");

                fprintf(stdout, "SOURCE      Physical Address - [");        // 출발지 Eth주소 출력
                for(int iCnt = 0 ; iCnt < 6 ; ++iCnt)
                 {
                   fprintf(stdout, "%02X:", pEth->ether_shost[iCnt]);
                 }
                 fprintf(stdout, "\b]\n");


                 // 프로토콜 16진수
                fprintf(stdout, "next protocal                - [0x%04x]   (", ntohs(pEth->ether_type));


                 // 프로토콜 형식 출력
                switch(ntohs(pEth->ether_type))
                 {
                   case 0x0800:
                   fprintf(stdout, "IP) 입니다.\n");
                   break;

                  case 0x0200:
                   fprintf(stdout, "PUP) 입니다.\n");
                   return -100;

                  case 0x0860:
                   fprintf(stdout, "ARP) 입니다.\n");
                   return -100;

                  case 0x8035:
                   fprintf(stdout, "RARP) 입니다.\n");
                   return -100;

                  default:
                   fprintf(stdout,"...) 알수없는 형식입니다.\n");
                   return -100;
                 }
                /* Eth 헤더 출력부 끝 */

                /* Ip 헤더 출력부 시작*/
                  fprintf(stdout, "SOURCE IP          - [%s]\n", inet_ntoa(pIph->ip_src)); // 출발지 IP
                  fprintf(stdout, "DESTINATION IP     - [%s]\n", inet_ntoa(pIph->ip_dst)); // 도착지 IP
                  /* Ip 헤더 출력부 끝*/

                  /* TCP 헤더 출력부 시작*/
                   // 출발지 TCP
                   fprintf(stdout, "SOURCE PORT          - [%u]\n", ntohs(pTph->th_sport));
                  // 도착지 TCP
                   fprintf(stdout, "DESTINATION PORT     - [%u]\n", ntohs(pTph->th_dport));
                   printf("================================================================\n\n");
                   /* TCP 헤더 출력부 끝*/

        }

       /* And close the session */
       pcap_close(handle);
       return(0);
    }
