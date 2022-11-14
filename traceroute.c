/* Kacper Solecki, 316720 */
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <poll.h>
#include <assert.h>

#include "traceroute.h"

/* Returns time since Epoch in miliseconds */
timestamp_t get_current_timestamp(){
    struct timeval tv;
    if(gettimeofday(&tv, NULL) < 0){
        fprintf(stderr, "gettimeofday error: %s\n", strerror(errno)); 
		exit(EXIT_FAILURE);
    }
    return (timestamp_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

/* Checking input address */
int is_valid_ip_address(char *addr){
    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, addr, &(sa.sin_addr));
    return result != 0;
}

u_int16_t compute_icmp_checksum (const void *buff, int length){
	u_int32_t sum;
	const u_int16_t* ptr = buff;
	assert (length % 2 == 0);
	for (sum = 0; length > 0; length -= 2)
		sum += *ptr++;
	sum = (sum >> 16) + (sum & 0xffff);
	return (u_int16_t)(~(sum + (sum >> 16)));
}

/* Sends a single packet via given socket, with TTL ttl, identifer id,
 * sequence number seq to address addr. Returns sending timestamp 
 */
timestamp_t send_packet(int sockfd, int *ttl, uint16_t id, uint16_t seq, char *addr){
    struct icmp header;
    header.icmp_type = ICMP_ECHO;
    header.icmp_code = 0;
    header.icmp_hun.ih_idseq.icd_id = id;
    header.icmp_hun.ih_idseq.icd_seq = seq;
    header.icmp_cksum = 0;
    header.icmp_cksum = compute_icmp_checksum(
        (u_int16_t*)&header, sizeof(header));

    struct sockaddr_in recipient;
    bzero (&recipient, sizeof(recipient));
    recipient.sin_family = AF_INET;
    inet_pton(AF_INET, addr, &recipient.sin_addr);
    if(setsockopt(sockfd, IPPROTO_IP, IP_TTL, ttl, sizeof(int)) < 0){
        fprintf(stderr, "setsockopt error: %s\n", strerror(errno)); 
		exit(EXIT_FAILURE);
    }
    timestamp_t sent_time = get_current_timestamp();
    if(sendto(
        sockfd,
        &header,
        sizeof(header),
        0,
        (struct sockaddr*)&recipient,
        sizeof(recipient)
    ) < 0){
        fprintf(stderr, "sendto error: %s\n", strerror(errno)); 
		exit(EXIT_FAILURE);
    }
    return sent_time;
}

/* Reads all packets from given socket, ignoring those with identifier other
 * than id or sequence number not in range [first_seq, first_seq + NPACKETS].
 * Fills IP of senders into sender_ip_str and transforms sending times
 * given in times into rrts
 */
int recieve(int sockfd, uint16_t id, char sender_ip_str[][20], timestamp_t *times, int first_seq){
    int packets_recieved = 0;
    struct sockaddr_in sender;	
    socklen_t sender_len = sizeof(sender);
    u_int8_t buffer[IP_MAXPACKET];

    /* read packets while there are any */
    while(1){
        ssize_t packet_len = recvfrom(
            sockfd,
            buffer,
            IP_MAXPACKET,
            MSG_DONTWAIT,
            (struct sockaddr*)&sender,
            &sender_len
        );
        if (packet_len < 0) {
            if(errno == EWOULDBLOCK)
                break;
            fprintf(stderr, "recvfrom error: %s\n", strerror(errno)); 
            exit(EXIT_FAILURE);
        }        

        /* frames created by responding router */
        struct ip* outer_ip_header = (struct ip*) buffer;
        u_int8_t* outer_icmp_packet = buffer + 4 * outer_ip_header->ip_hl;
        struct icmp* outer_icmp_header = (struct icmp*) outer_icmp_packet;

        /* structure in which proper id and seqence number are located */
        struct icmp* icmp_header = outer_icmp_header;

        /* ttl exceeded */
        if(outer_icmp_header->icmp_type == 11){
            struct ip* ip_header = (struct ip*) (outer_icmp_packet + 8);
            u_int8_t* icmp_packet = (uint8_t*)ip_header + 4 * ip_header->ip_hl;
            icmp_header = (struct icmp*) icmp_packet;
        }

        uint16_t seq = icmp_header->icmp_seq;
        if(icmp_header->icmp_hun.ih_idseq.icd_id != id)
            continue;
        if(seq < first_seq || seq >= first_seq + NPACKETS)
            continue;

        packets_recieved++;

        int packet_idx = seq % NPACKETS;
        if(!inet_ntop(AF_INET, &(sender.sin_addr), sender_ip_str[packet_idx], 20)){
            fprintf(stderr, "inet_ntop error: %s\n", strerror(errno)); 
            exit(EXIT_FAILURE);
        }
        /* transform sending time ino rtt */
        times[packet_idx] = get_current_timestamp() - times[packet_idx];
    }
    return packets_recieved;
}

/* Recieves all responses to packets sent with given ttl and id to address addr
 * with sending times given in times. Prints responding servers' ips and rtts.
 * Returns 1 if packets have reached the final destination, else 0
 */
int recieve_all_packets(int sockfd, int ttl, uint16_t id, char *addr, timestamp_t *times){
    struct pollfd pfd;
    pfd.fd = sockfd;
    pfd.events = POLLIN;

    char sender_ip_str[NPACKETS][20];

    int first_seq = ttl * NPACKETS - NPACKETS;
    int packets_recieved = 0;
    unsigned long long starttime = get_current_timestamp();

    while(packets_recieved < NPACKETS){
        unsigned long long currtime = get_current_timestamp();
        int time_past = currtime - starttime;
        /* timeout is meant for all packets with given ttl */
        if(time_past >= TIMEOUT)
            break;
        pfd.revents = 0;
        poll(&pfd, 1, TIMEOUT - time_past);
        if(pfd.revents & POLLIN)
            packets_recieved += recieve(sockfd, id, sender_ip_str, times, first_seq);
    }
    
    printf("%d. ", ttl);
    /* print unique IPs */
    if(packets_recieved > 0){
        for(int i = 0; i < NPACKETS; i++){
            if(times[i] != -1){
                int unique_address = 1;
                for(int j = 0; j < i ; j++){
                    if(times[j] != -1 && strcmp(sender_ip_str[i], sender_ip_str[j]) == 0)
                        unique_address = 0;
                }
                if(unique_address)
                    printf("%s ", sender_ip_str[i]);
            }
        }

        /* print rtt  */
        if(packets_recieved == NPACKETS){
            timestamp_t time_sum = 0;
            for(int i = 0; i < NPACKETS; i++)
                time_sum += times[i];
            printf("%lldms\n", time_sum / NPACKETS);
        }
        else
            printf("???\n");
    }
    else
        printf("*\n");
    
    /* reached the destination */
    for(int i = 0; i < NPACKETS; i++){
        if(strcmp(addr, sender_ip_str[i]) == 0)
            return 1;
    }
    return 0;
}
