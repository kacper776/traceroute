#include <netinet/ip_icmp.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#ifndef TRACEROUTE_H_
#define TRACEROUTE_H_

#define TTLMAX 30
#define NPACKETS 3
#define TIMEOUT 1000

typedef long long timestamp_t;

timestamp_t get_current_timestamp();

int is_valid_ip_address(char *addr);

u_int16_t compute_icmp_checksum(const void *buff, int length);

timestamp_t send_packet(int sockfd, int *ttl, uint16_t id, uint16_t seq, char *addr);

int recieve(int sockfd, uint16_t id, char sender_ip_str[][20], timestamp_t *times, int first_seq);

int recieve_all_packets(int sockfd, int ttl, uint16_t id, char *addr, timestamp_t *times);

#endif