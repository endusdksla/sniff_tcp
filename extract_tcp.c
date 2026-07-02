#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <string.h>
#include "./myheader.h"

void print_eth_mac(const u_char *mac){
    for(int i=0; i<6; i++){
        printf("%02x", mac[i]);
        if(i!=5) printf(":");
    }
}

void print_http_message(const u_char *payload, int len){
    // http method check
    if (strncmp((char *)payload, "GET ",    4) != 0 &&
        strncmp((char *)payload, "POST ",   5) != 0 &&
        strncmp((char *)payload, "PUT ",    4) != 0 &&
        strncmp((char *)payload, "HEAD ",   5) != 0 &&
        strncmp((char *)payload, "DELETE ", 7) != 0 &&
        strncmp((char *)payload, "HTTP/",   5) != 0)
        return;
    printf("[HTTP Message]\n");
    // maximum 1024(for terminal log...)
    int print_len = (len > 1024) ? 1024 : len;
    for(int i = 0; i < print_len; i++){
        putchar(payload[i]);
    }
    if (len > 1024)
        printf("\n... [%d more bytes not shown]\n", len - 1024);
    printf("\n");
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
    struct ethheader *eth = (struct ethheader *)packet;
    int eth_header_len = sizeof(struct ethheader);

    // ntohs: big endian to little endian
    if(ntohs(eth->ether_type) != 0x0800) return;
    struct ipheader *ip = (struct ipheader *)(packet + eth_header_len);
    int ip_header_len = ip->iph_ihl*4;
    
    if(ip->iph_protocol != IPPROTO_TCP) return;
    struct tcpheader *tcp = (struct tcpheader *)(packet + eth_header_len + ip->iph_ihl*4);

    int tcp_header_len = TH_OFF(tcp)*4;
    const u_char *payload = packet + eth_header_len + ip_header_len + tcp_header_len;
    int payload_len = ntohs(ip->iph_len) - ip_header_len - tcp_header_len;
    
    // print info(http only)
    /* http only filter */
    // if (ntohs(tcp->tcp_dport) != 80 && ntohs(tcp->tcp_sport) != 80) return;

    printf("===============================\n");
    printf("[Ethernet Header]\n");
    printf("    src Mac: ");
    print_eth_mac(eth->ether_shost);    printf("\n");
    printf("    dst Mac: ");
    print_eth_mac(eth->ether_dhost);    printf("\n");

    printf("[IP Header]\n");
    printf("    src IP: %s\n", inet_ntoa(ip->iph_sourceip));
    printf("    dst IP: %s\n", inet_ntoa(ip->iph_destip));

    printf("[TCP Header]\n");
    printf("    src Port: %d\n", ntohs(tcp->tcp_sport));
    printf("    dst Port: %d\n", ntohs(tcp->tcp_dport));
    if(payload_len > 0){
        print_http_message(payload, payload_len);
    }
    printf("\n");
}

int main(){
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net;

    handle = pcap_open_live("en0", BUFSIZ, 1, 1000, errbuf);

    pcap_compile(handle, &fp, filter_exp, 0, net);
    if(pcap_setfilter(handle, &fp) != 0){
        pcap_perror(handle, "Error: ");
        exit(EXIT_FAILURE);
    }

    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);
    return 0;
}
