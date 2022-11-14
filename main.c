/* Kacper Solecki, 316720 */
#include "traceroute.h"

int main(int argc, char **argv)
{
    if(argc != 2){
        fprintf(stderr, "usage: %s <ip>\n", argv[0]);
        return EXIT_FAILURE;
    }
    if(!is_valid_ip_address(argv[1])){
        fprintf(stderr, "Not a valid IPV4 address\n");
        return EXIT_FAILURE;
    }
	int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (sockfd < 0) {
		fprintf(stderr, "socket error: %s\n", strerror(errno)); 
		return EXIT_FAILURE;
	}

    uint16_t seq = 0;
    /* main loop of program */
    for(int ttl = 1; ttl <= TTLMAX; ttl++){
        timestamp_t times[NPACKETS];
        for(int i = 0; i < NPACKETS; i++){
            times[i] = send_packet(sockfd, &ttl, getpid(), seq, argv[1]);
            seq++;
        }
        if(recieve_all_packets(sockfd, ttl, getpid(), argv[1], times))
            break;
    }

	return EXIT_SUCCESS;
}