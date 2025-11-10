// ---------------------------------------------------------------------
// SPDX-License-Identifier: GPL-3.0-or-later
// packet.c is a part of Blitzping.
// ---------------------------------------------------------------------

#include "socket.h"
#include "packet.h"

/* WORK IN-PROGRESS */



static int send_loop(void *arg) {
    const struct ProgramArgs *const program_args =
            (const struct ProgramArgs *const)arg;

    srand(time(0));

    _Alignas (_Alignof (max_align_t)) uint8_t
            packet_buffer[IP_PKT_MTU] = {0};

    struct ip_hdr  *ip_header  =
            (struct ip_hdr *)packet_buffer;
    struct tcp_hdr *tcp_header =
            (struct tcp_hdr *)(packet_buffer + sizeof (struct ip_hdr));

    *ip_header = *(program_args->ipv4);

    *tcp_header = (struct tcp_hdr){
            .sport = htons(rand() % 65536),
            .dport = htons(80),
            .seqnum = rand(),
            .flags.syn = true
    };


    uint32_t ip_diff = 1;
    struct sockaddr_in dest_info = {
            .sin_family = AF_INET,
            .sin_port = ntohs(tcp_header->dport),
            .sin_addr.s_addr = ntohl(ip_header->daddr.address)
    };

    int connection_status = connect(
            program_args->socket,
            (struct sockaddr *)&dest_info,
            sizeof(dest_info)
    );

    if (connection_status != 0) {
        logger(LOG_ERROR,
               "Failed to bind socket to the destination address: %s",
               strerror(errno)
        );
        return 1;
    }

    size_t packet_length = ntohs(ip_header->len);

    _Alignas (_Alignof (max_align_t)) struct iovec iov[UIO_MAXIOV];
    for (int i = 0; i < 37; i++) {
        iov[i].iov_base = packet_buffer;
        iov[i].iov_len = packet_length;
    }

    if (!program_args->advanced.no_cpu_prefetch) {
        PREFETCH(packet_buffer, 1, 3);
        PREFETCH(iov, 0, 3);
    }

    uint32_t next_ip;
    uint16_t next_port;
    ssize_t bytes_written;

    struct pollfd pfd;
    pfd.fd = program_args->socket;
    pfd.events = POLLOUT;

    for (;;) {
        // Randomize source IP and port for the next packet
        next_ip = htonl(
                program_args->ipv4->saddr.address
                + (rand() % ip_diff)
        );
        next_port = htons(rand() % 65536);

        bytes_written = writev(program_args->socket, iov, 37);

        if (bytes_written == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                if (poll(&pfd, 1, -1) == -1) {
                    logger(LOG_ERROR,
                           "Failed to poll the socket: %s",
                           strerror(errno)
                    );
                    break;
                }
            }
            else {
                logger(LOG_ERROR,
                       "Failed to write packet to the socket: %s",
                       strerror(errno)
                );
                break;
            }
        }
        else if (bytes_written < (ssize_t)(packet_length * 37)) {
            logger(LOG_WARN,
                   "Not all data was written; %ld bytes remain;\n"
                   "try to lower the buffer size passed to writev().",
                   (packet_length * 37) - bytes_written
            );
        }

        ip_header->saddr.address = next_ip;
        tcp_header->sport = next_port;
    }

#if __STDC_VERSION__ >= 201112L && !defined(__STDC_NO_THREADS__)
    return thrd_success;
#else
    return 0;
#endif
}


#include <time.h>
#include <poll.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>

// Constants tuned for traceroute behavior
#ifndef TRACERT_MAX_TTL
# define TRACERT_MAX_TTL 5
#endif
#ifndef TRACERT_PROBES_PER_TTL
# define TRACERT_PROBES_PER_TTL 1
#endif
#ifndef TRACERT_TIMEOUT_MS
# define TRACERT_TIMEOUT_MS 2000
#endif

// This function replaces the old send_loop when running traceroute-style probes.
// It sends TRACERT_PROBES_PER_TTL probes for each TTL value from 1..TRACERT_MAX_TTL,
// listens for ICMP replies, matches them to probes using the quoted transport header
// (we use the TCP source port as the token), and records RTT and responder IP.
static int send_loop_tracert(void *arg) {
    const struct ProgramArgs *const program_args =
            (const struct ProgramArgs *const)arg;

    // local buffers
    _Alignas(_Alignof(max_align_t)) uint8_t packet_buffer[IP_PKT_MTU] = {0};
    struct ip_hdr  *ip_header  = (struct ip_hdr *)packet_buffer;
    struct udp_hdr *udp_header = (struct udp_hdr *)(packet_buffer + sizeof(struct ip_hdr));

    // initialize template headers from program args
    *ip_header = *(program_args->ipv4);
    ip_header->proto = IPPROTO_UDP; // use UDP

    // base UDP template (destination port will be varied)
    *udp_header = (struct udp_hdr){
            .sport = htons(33434),
            .dport = htons(33434),
            .len   = htons(sizeof(struct udp_hdr)), // only header, no payload
            .chksum = 0
    };

    size_t packet_length = sizeof(struct ip_hdr) + sizeof(struct udp_hdr);
    ip_header->len = htons(packet_length);

    // Destination info
    struct sockaddr_in dest_info = {
            .sin_family = AF_INET,
            .sin_port = udp_header->dport,
            .sin_addr.s_addr = ntohl(ip_header->daddr.address)
    };

    // Create ICMP socket to receive replies
    int icmp_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (icmp_sock == -1) {
        logger(LOG_ERROR, "send_loop_tracert: failed to create ICMP socket: %s", strerror(errno));
        return 1;
    }

    // Non-blocking ICMP socket
    int flags = fcntl(icmp_sock, F_GETFL, 0);
    if (flags != -1)
        fcntl(icmp_sock, F_SETFL, flags | O_NONBLOCK);

    struct pollfd pfd = {
            .fd = icmp_sock,
            .events = POLLIN
    };

    struct sent_probe {
        uint16_t sport;
        struct timespec ts;
        bool answered;
        struct sockaddr_in responder;
        long rtt_ms;
    } probes[TRACERT_PROBES_PER_TTL];

    uint8_t recvbuf[2048];

    // TTL loop
    for (int ttl = 1; ttl <= TRACERT_MAX_TTL; ++ttl) {
        for (int i = 0; i < TRACERT_PROBES_PER_TTL; ++i) {
            probes[i].answered = false;
            probes[i].rtt_ms = -1;
            memset(&probes[i].responder, 0, sizeof(probes[i].responder));
        }

        for (int p = 0; p < TRACERT_PROBES_PER_TTL; ++p) {
            // unique source port (so we can identify replies)
            uint16_t token = (uint16_t)((getpid() & 0xffff) ^ (ttl << 8) ^ p);
            udp_header->sport = htons(token);
            udp_header->dport = htons(33434 + ttl); // vary dest port per hop

            ip_header->ttl = (uint8_t)ttl;

            // timestamp
            clock_gettime(CLOCK_MONOTONIC, &probes[p].ts);
            probes[p].sport = udp_header->sport;

            // send packet
            ssize_t sent = sendto(program_args->socket, packet_buffer, packet_length, 0,
                                  (struct sockaddr *)&dest_info, sizeof(dest_info));
            if (sent == -1)
                logger(LOG_WARN, "sendto failed (ttl=%d probe=%d): %s", ttl, p, strerror(errno));
        }

        // listen for ICMP replies
        int remaining_ms = TRACERT_TIMEOUT_MS;
        int unanswered = TRACERT_PROBES_PER_TTL;
        while (remaining_ms > 0 && unanswered > 0) {
            int n = poll(&pfd, 1, remaining_ms);
            if (n == -1) {
                if (errno == EINTR) continue;
                logger(LOG_ERROR, "poll failed: %s", strerror(errno));
                break;
            }
            if (n == 0)
                break;

            struct sockaddr_in src_addr;
            socklen_t addrlen = sizeof(src_addr);
            ssize_t rlen = recvfrom(icmp_sock, recvbuf, sizeof(recvbuf), 0,
                                    (struct sockaddr *)&src_addr, &addrlen);
            if (rlen <= 0) continue;

            struct ip_hdr *outer_ip = (struct ip_hdr *)recvbuf;
            int outer_ihl = (outer_ip->ihl & 0x0f) * 4;
            if (rlen < outer_ihl + 8) continue;

            uint8_t *icmp_ptr = recvbuf + outer_ihl;
            uint8_t icmp_type = icmp_ptr[0];
            //uint8_t icmp_code = icmp_ptr[1];

            if (icmp_type != 11 && icmp_type != 3)
                continue; // only handle Time Exceeded and Dest Unreachable

            uint8_t *quoted_ptr = icmp_ptr + 8;
            struct ip_hdr *quoted_ip = (struct ip_hdr *)quoted_ptr;
            int q_ihl = (quoted_ip->ihl & 0x0f) * 4;
            struct udp_hdr *quoted_udp = (struct udp_hdr *)((uint8_t *)quoted_ip + q_ihl);

            uint16_t quoted_sport = quoted_udp->sport;

            for (int i = 0; i < TRACERT_PROBES_PER_TTL; ++i) {
                if (!probes[i].answered && probes[i].sport == quoted_sport) {
                    struct timespec now;
                    clock_gettime(CLOCK_MONOTONIC, &now);
                    long ms = (now.tv_sec - probes[i].ts.tv_sec) * 1000L +
                              (now.tv_nsec - probes[i].ts.tv_nsec) / 1000000L;
                    probes[i].answered = true;
                    probes[i].rtt_ms = ms;
                    probes[i].responder = src_addr;
                    unanswered--;
                    break;
                }
            }
            remaining_ms = 0; // single poll pass for simplicity
        }

        // Print results
        for (int i = 0; i < TRACERT_PROBES_PER_TTL; ++i) {
            if (probes[i].answered) {
                char ipstr[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &probes[i].responder.sin_addr, ipstr, sizeof(ipstr));
                logger(LOG_INFO, "ttl=%d probe=%d reply from %s rtt=%ld ms", ttl, i, ipstr, probes[i].rtt_ms);
            } else {
                logger(LOG_INFO, "ttl=%d probe=%d no reply", ttl, i);
            }
        }

        bool reached = false;
        for (int i = 0; i < TRACERT_PROBES_PER_TTL; ++i) {
            if (probes[i].answered &&
                probes[i].responder.sin_addr.s_addr == dest_info.sin_addr.s_addr) {
                reached = true;
                break;
            }
        }
        if (reached) {
            logger(LOG_INFO, "Destination reached at ttl=%d; stopping traceroute.", ttl);
            break;
        }
    }

    close(icmp_sock);

#if __STDC_VERSION__ >= 201112L && !defined(__STDC_NO_THREADS__)
    return thrd_success;
#else
    return 0;
#endif
}


static int send_loop_dpdk(void *arg) {
    const struct ProgramArgs *const program_args =
            (const struct ProgramArgs *const)arg;

    _Alignas (_Alignof (max_align_t)) uint8_t
            packet_buffer[IP_PKT_MTU] = {0};

    struct ip_hdr  *ip_header  =
            (struct ip_hdr *)packet_buffer;
    struct tcp_hdr *tcp_header =
            (struct tcp_hdr *)(packet_buffer + sizeof (struct ip_hdr));

    *ip_header = *(program_args->ipv4);
    *tcp_header = (struct tcp_hdr){
            .sport = htons(rand() % 65536),
            .dport = htons(80),
            .seqnum = rand(),
            .flags.syn = true
    };

    uint32_t ip_diff = 1;
    size_t packet_length = ntohs(ip_header->len);

    const uint16_t port_id = 0;

    for (;;) {
        ip_header->saddr.address = htonl(
                program_args->ipv4->saddr.address
                + (rand() % ip_diff)
        );
        tcp_header->sport = htons(rand() % 65536);

        if (dpdk_send_packet(port_id, packet_buffer, packet_length) != 0) {
            // logger(LOG_WARN, "Failed to send DPDK packet");
        }
    }

#if __STDC_VERSION__ >= 201112L && !defined(__STDC_NO_THREADS__)
    return thrd_success;
#else
    return 0;
#endif
}



// TODO: Use xorshift
// TODO: check for POSIX_MEMLOCK
int send_packets(struct ProgramArgs *const program_args) {

    if (!program_args->advanced.no_mem_lock) {
        if (mlockall(MCL_FUTURE) == -1) {
            logger(LOG_ERROR,
                   "Failed to lock memory: %s", strerror(errno)
            );
            return 1;
        }
        else {
            logger(LOG_INFO, "Locked memory.");
        }
    }

    // TODO: See if this is required for a raw sendto()?
    /*
    struct sockaddr_in dest_info;
    dest_info.sin_family = AF_INET;
    dest_info.sin_port = tcp_header->dport;
    dest_info.sin_addr.s_addr = ip_header->daddr.address;
    size_t packet_length = ntohs(ip_header->len);
    struct sockaddr *dest_addr = (struct sockaddr *)&dest_info;
    size_t addr_len = sizeof (dest_info);
    */

    /*struct msghdr msg = {
        .msg_name = &(struct sockaddr_in){
            .sin_family = AF_INET,
            .sin_port = tcp_header->dport,
            .sin_addr.s_addr = ip_header->daddr.address
        },
        .msg_namelen = sizeof (struct sockaddr_in),
        .msg_iov = (struct iovec[1]){
            {
                .iov_base = packet_buffer,
                .iov_len = ntohs(ip_header->len)
            }
        },
        .msg_iovlen = 1
    };*/

    /*
    printf("Packet:\n");
    printf("Source IP: %s\n", inet_ntoa(*(struct in_addr*)&ip_header->saddr.address));
    printf("Destination IP: %s\n", inet_ntoa(*(struct in_addr*)&ip_header->daddr.address));
    printf("Source Port: %d\n", ntohs(tcp_header->sport));
    printf("Destination Port: %d\n", ntohs(tcp_header->dport));
    printf("TTL: %d\n", ip_header->ttl);
    printf("Header Length: %d\n", ip_header->ihl * 4); // ihl is in 32-bit words
    printf("Total Length: %d\n", ntohs(ip_header->len));
    printf("SYN Flag: %s\n", tcp_header->flags.syn ? "Set" : "Not set");
    printf("\n");
    */



    unsigned int num_threads = program_args->advanced.num_threads;

    thrd_start_t send_func;

    if (program_args->advanced.use_dpdk) {
        if (program_args->advanced.tracert) {
            logger(LOG_ERROR, "Traceroute mode is not compatible with DPDK.");
            return 1;
        }
        logger(LOG_INFO, "Using DPDK send loop.");
        send_func = send_loop_dpdk;
    } else {
        if (program_args->advanced.tracert) {
            logger(LOG_INFO, "Using POSIX traceroute loop.");
            send_func = send_loop_tracert;
        } else {
            logger(LOG_INFO, "Using POSIX send loop.");
            send_func = send_loop;
        }
    }

    if (num_threads == 0) {
        send_func(program_args);
    }
    else {
#if __STDC_VERSION__ >= 201112L && !defined(__STDC_NO_THREADS__)
        logger(LOG_INFO, "Spawning %u threads.", num_threads);
        thrd_t threads[MAX_THREADS];

        for (unsigned int i = 0; i < num_threads; i++) {
            int thread_status = thrd_create(
                &threads[i], send_func, program_args
            );
            if (thread_status != thrd_success) {
                logger(LOG_ERROR, "Failed to spawn thread %d.", i);
                // Cleanup already-created threads
                for (unsigned int j = 0; j < i; j++) {
                    thrd_join(threads[j], NULL);
                }
                //free(threads);
                return 1;
            }
        }

        // TODO: This is never reached; add a signal handler?
        for (unsigned int i = 0; i < num_threads; i++) {
            thrd_join(threads[i], NULL);
        }
#else
        return 1;
#endif
    }


    if (!program_args->advanced.no_mem_lock) {
        if (munlockall() == -1) {
            logger(LOG_ERROR,
                   "Failed to unlock used memory: %s", strerror(errno)
            );
            return 1;
        }
        else {
            logger(LOG_INFO, "Unlocked used memory.");
        }
    }

    return 0;
}


// ---------------------------------------------------------------------
// END OF FILE: packet.c
// ---------------------------------------------------------------------
