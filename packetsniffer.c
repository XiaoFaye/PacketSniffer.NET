#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <errno.h>

#if (defined(__APPLE__) && defined(__MACH__)) || defined(__FreeBSD__)
    #include <err.h>
    #include <net/if.h>
    #include <net/bpf.h>
    #include <fcntl.h>
#else
    #include <netinet/ip_icmp.h>   //Provides declarations for icmp header
    #include <netinet/if_ether.h>  //For ETH_P_ALL
#endif

typedef struct PacketData {
    int  length;
    int  s_port;
    int  d_port;
    char *protocal;
    char *s_addr;
    char *d_addr;
}packetData;

#if (defined(__APPLE__) && defined(__MACH__)) || defined(__FreeBSD__)

int open_dev()
{
    int fd = -1;
    char dev[32];
    int i = 0;


    /* Open the bpf device */
    for (i = 0; i < 255; i++) {
        (void)snprintf(dev, sizeof(dev), "/dev/bpf%u", i);

        (void)printf("Trying to open: %s\n", dev);

        fd = open(dev, O_RDWR);
        if (fd > -1)
            return fd;

        switch (errno) {
            case EBUSY:
                break;
            default:
                return -1;
        }
    }

    errno = ENOENT;
    return -1;
}

int check_dlt(int fd)
{
    u_int32_t dlt = 0;

    /* Ensure we are dumping the datalink we expect */
    if(ioctl(fd, BIOCGDLT, &dlt) < 0)
        return -1;

    (void)fprintf(stdout, "datalink type=%u\n", dlt);

    switch (dlt) {
        case DLT_EN10MB:
            return 0;
        default:
            (void)fprintf(stderr, "Unsupported datalink type:%u", dlt);
            errno = EINVAL;
            return -1;
    }
}

int set_options(int fd, char *iface)
{
    struct ifreq ifr;
    u_int32_t enable = 1;


    /* Associate the bpf device with an interface */
    (void)strlcpy(ifr.ifr_name, iface, sizeof(ifr.ifr_name)-1);

    if(ioctl(fd, BIOCSETIF, &ifr) < 0)
        return -1;

    /* Set header complete mode */
    if(ioctl(fd, BIOCSHDRCMPLT, &enable) < 0)
        return -1;

    /* Monitor packets sent from our interface */
    if(ioctl(fd, BIOCSSEESENT, &enable) < 0)
        return -1;

    /* Return immediately when a packet received */
    if(ioctl(fd, BIOCIMMEDIATE, &enable) < 0)
        return -1;

    return 0;
}

#endif

void ProcessPacket(unsigned char* buffer, packetData* data)
{
    struct tcphdr* tcp_header;
    struct udphdr* udp_header;
    u_int sourPort, destPort;
    struct ip *ip = (struct ip *)((const u_char*)buffer + sizeof(struct ether_header));
    char temp[INET_ADDRSTRLEN];
                    
    switch(ip->ip_p){
        case IPPROTO_TCP:
            data->protocal = "Tcp";
            
            tcp_header = (struct tcphdr*) ((char *) ip + (ip->ip_hl * 4));

            sourPort = ntohs(tcp_header->th_sport);
            destPort = ntohs(tcp_header->th_dport);

            data->s_port = sourPort;
            data->d_port = destPort;

            data->s_addr = strdup(inet_ntop(AF_INET, &ip->ip_src.s_addr, temp, sizeof(temp)));
            data->d_addr = strdup(inet_ntop(AF_INET, &ip->ip_dst.s_addr, temp, sizeof(temp)));

            break;
        case IPPROTO_UDP:
            data->protocal = "Udp";
            
            udp_header = (struct udphdr*) ((char *) ip + (ip->ip_hl * 4));

            sourPort = ntohs(udp_header->uh_sport);
            destPort = ntohs(udp_header->uh_dport);

            data->s_port = sourPort;
            data->d_port = destPort;

            data->s_addr = strdup(inet_ntop(AF_INET, &ip->ip_src.s_addr, temp, sizeof(temp)));
            data->d_addr = strdup(inet_ntop(AF_INET, &ip->ip_dst.s_addr, temp, sizeof(temp)));
            
            break;
        case IPPROTO_ICMP:
            data->protocal = "Icmp";

            data->s_addr = strdup(inet_ntop(AF_INET, &ip->ip_src.s_addr, temp, sizeof(temp)));
            data->d_addr = strdup(inet_ntop(AF_INET, &ip->ip_dst.s_addr, temp, sizeof(temp)));

            break;
        case IPPROTO_IP:
            data->protocal = "IP";

            break;
        default:
            data->protocal = "Unspecified";

            break;
    }
}

#if (defined(__APPLE__) && defined(__MACH__)) || defined(__FreeBSD__)

int capture(char *iface, void (*ptr)(packetData*))
{
    int fd = 0;

    if (iface == NULL)
        err(EXIT_FAILURE, "strdup");

    fd = open_dev();
    if (fd < 0)
        err(EXIT_FAILURE, "open_dev");

    if (set_options(fd, iface) < 0)
        err(EXIT_FAILURE, "set_options");

    if (check_dlt(fd) < 0)
        err(EXIT_FAILURE, "check_dlt");

    char *buf = NULL;
    char *p = NULL;
    size_t blen = 0;
    ssize_t n = 0;
    struct bpf_hdr *bh = NULL;
    struct ether_header *eh = NULL;

    packetData *data;
    data = malloc(sizeof(packetData));
    data->s_port = 0;
    data->d_port = 0;
    data->protocal = "";
    data->s_addr = "";
    data->d_addr = "";

    if(ioctl(fd, BIOCGBLEN, &blen) < 0)
        return -1;

    if ( (buf = malloc(blen)) == NULL)
        return -1;

    (void)printf("reading packets ...\n");

    for ( ; ; ) {
        (void)memset(buf, '\0', blen);

        n = read(fd, buf, blen);

        if (n <= 0)
            return -1;

        p = buf;
        while (p < buf + n) {
            bh = (struct bpf_hdr *)p;

            /* Start of ethernet frame */
            eh = (struct ether_header *)(p + bh->bh_hdrlen);

            data->length = bh->bh_datalen;

            u_short ether_type = ntohs(eh->ether_type);
            switch (ether_type)
            {
                case ETHERTYPE_IP:
                    ProcessPacket((unsigned char*)eh, data);
                    
                    break;
                default:
                    data->protocal = "Unspecified";
            }
            (*ptr) (data);
            p += BPF_WORDALIGN(bh->bh_hdrlen + bh->bh_caplen);
        }
    }

    return 0;
}

#else

int capture(char *iface, void (*ptr)(packetData*))
{
    int saddr_size , data_size;
    struct sockaddr saddr;

    packetData *data;
    data = malloc(sizeof(packetData));
    data->s_port = 0;
    data->d_port = 0;
    data->protocal = "";
    data->s_addr = "";
    data->d_addr = "";
         
    unsigned char *buffer = (unsigned char *) malloc(65536);
    
    printf("Starting...\n");
     
    int sock_raw = socket( AF_PACKET , SOCK_RAW , htons(ETH_P_ALL)) ;
     
    if(sock_raw < 0)
    {
        //Print the error with proper message
        perror("Socket Error");
        return 1;
    }

    while(1)
    {
        saddr_size = sizeof saddr;
        //Receive a packet
        data_size = recvfrom(sock_raw , buffer , 65536 , 0 , &saddr , (socklen_t*)&saddr_size);
        if(data_size < 0)
        {
            printf("Recvfrom error , failed to get packets\n");
            return 1;
        }
        data->length = data_size;
        //Now process the packet
        ProcessPacket((unsigned char*)buffer , data);
        (*ptr) (data);
    }
    close(sock_raw);

    return 0;
}

#endif