#include <arpa/inet.h> // 메인에서 헤더를 포함하니까 여기에는 없어도 될듯

/* Ethernet Header */
struct ethheader {
    u_char  ether_dhost[6];   /* destination MAC address */
    u_char  ether_shost[6];   /* source MAC address */
    u_short ether_type;       /* protocol type: 0x0800 = IP */
};

/* IP Header */
struct ipheader {
    unsigned char      iph_ihl:4,        /* IP header length */
                       iph_ver:4;        /* IP version */
    unsigned char      iph_tos;          /* type of service */
    unsigned short int iph_len;          /* IP packet length (data + header) */
    unsigned short int iph_ident;        /* identification */
    unsigned short int iph_flag:3,       /* fragmentation flags */
                       iph_offset:13;    /* flags offset */
    unsigned char      iph_ttl;          /* time to live */
    unsigned char      iph_protocol;     /* protocol type */
    unsigned short int iph_chksum;       /* IP datagram checksum */
    struct  in_addr    iph_sourceip;     /* source IP address */
    struct  in_addr    iph_destip;       /* destination IP address */
};

/* TCP Header */
struct tcpheader {
    u_short tcp_sport;    /* source port */
    u_short tcp_dport;    /* destination port */
    u_int   tcp_seq;      /* sequence number */
    u_int   tcp_ack;      /* acknowledgement number */
    u_char  tcp_offx2;    /* data offset, rsvd */
#define TH_OFF(th) (((th)->tcp_offx2 & 0xf0) >> 4)
    u_char  tcp_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short tcp_win;      /* window */
    u_short tcp_sum;      /* checksum */
    u_short tcp_urp;      /* urgent pointer */
};
