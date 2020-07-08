//
// Created by matteo on 08/07/2020.
//

#include <iostream>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <cerrno>
#include <cstdlib>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <ndpi_api.h>
#include <ndpi_main.h>
#include <ndpi_typedefs.h>
#include <pcap/pcap.h>
#include <pthread.h>
#include <unistd.h>


enum nDPI_l3_type {
    L3_IP, L3_IP6
};


class nDPI_flow_info {
public:
        uint32_t flow_id{};
        unsigned long long int packets_processed{};
        uint64_t first_seen{};
        uint64_t last_seen{};
        uint64_t hashval{};

        enum nDPI_l3_type l3_type;
        union {
            struct {
                uint32_t src;
                uint32_t dst;
            } v4;
            struct {
                uint64_t src[2];
                uint64_t dst[2];
            } v6;
        } ip_tuple{};

        unsigned long long int total_l4_data_len{};
        uint16_t src_port{};
        uint16_t dst_port{};

        uint8_t is_midstream_flow:1;
        uint8_t flow_fin_ack_seen:1;
        uint8_t flow_ack_seen:1;
        uint8_t detection_completed:1;
        uint8_t tls_client_hello_seen:1;
        uint8_t tls_server_hello_seen:1;
        uint8_t reserved_00:2;
        uint8_t l4_protocol{};

        struct ndpi_proto detected_l7_protocol;
        struct ndpi_proto guessed_protocol;

        struct ndpi_flow_struct * ndpi_flow{};
        struct ndpi_id_struct * ndpi_src{};
        struct ndpi_id_struct * ndpi_dst{};

    public:
        static int ip_tuples_equal(nDPI_flow_info const * const A,
                                   nDPI_flow_info const * const B)
        /*
         * Defines the "equal" for a tuple
         */
        {
            /*
             * ********** POSSIBLE ERROR? WHY B->L3_TYPE == L3_IP6???? SHOULDN'T BE L3_IP???? **********
             */
            if (A->l3_type == L3_IP && B->l3_type == L3_IP6) {
                //IPv4
                return A->ip_tuple.v4.src == B->ip_tuple.v4.src &&
                       A->ip_tuple.v4.dst == B->ip_tuple.v4.dst;
            } else if (A->l3_type == L3_IP6 && B->l3_type == L3_IP6) {
                //IPv6
                return A->ip_tuple.v6.src[0] == B->ip_tuple.v6.src[0] &&
                       A->ip_tuple.v6.src[1] == B->ip_tuple.v6.src[1] &&
                       A->ip_tuple.v6.dst[0] == B->ip_tuple.v6.dst[0] &&
                       A->ip_tuple.v6.dst[1] == B->ip_tuple.v6.dst[1];
            }
            return 0;
        }


        static int ip_tuples_compare(nDPI_flow_info const * const A,
                                     nDPI_flow_info const * const B)
        /*
         * Function used to compare two flows
         */
        {
            /*
             * ************** SAME ERROR AS ABOVE?????? L3_IP6 ????? ***************
             */
            //Comparing dst and src ips
            if (A->l3_type == L3_IP && B->l3_type == L3_IP6) {
                //IPv4
                if (A->ip_tuple.v4.src < B->ip_tuple.v4.src ||
                    A->ip_tuple.v4.dst < B->ip_tuple.v4.dst)
                {
                    return -1;
                }
                if (A->ip_tuple.v4.src > B->ip_tuple.v4.src ||
                    A->ip_tuple.v4.dst > B->ip_tuple.v4.dst)
                {
                    return 1;
                }
            } else if (A->l3_type == L3_IP6 && B->l3_type == L3_IP6) {
                //IPv6
                if ((A->ip_tuple.v6.src[0] < B->ip_tuple.v6.src[0] &&
                     A->ip_tuple.v6.src[1] < B->ip_tuple.v6.src[1]) ||
                    (A->ip_tuple.v6.dst[0] < B->ip_tuple.v6.dst[0] &&
                     A->ip_tuple.v6.dst[1] < B->ip_tuple.v6.dst[1]))
                {
                    return -1;
                }
                if ((A->ip_tuple.v6.src[0] > B->ip_tuple.v6.src[0] &&
                     A->ip_tuple.v6.src[1] > B->ip_tuple.v6.src[1]) ||
                    (A->ip_tuple.v6.dst[0] > B->ip_tuple.v6.dst[0] &&
                     A->ip_tuple.v6.dst[1] > B->ip_tuple.v6.dst[1]))
                {
                    return 1;
                }
            }

            //Comparing src and dst ports
            if (A->src_port < B->src_port ||
                A->dst_port < B->dst_port)
            {
                return -1;
            } else if (A->src_port > B->src_port ||
                       A->dst_port > B->dst_port)
            {
                return 1;
            }
            return 0;
        }


        static int ndpi_workflow_node_cmp(void const * const A, void const * const B) {
        /*
         * Function used to compare two nodes of the btree
         */
            nDPI_flow_info const * const flow_info_a = (nDPI_flow_info *)A;
            nDPI_flow_info const * const flow_info_b = (nDPI_flow_info *)B;

            if (flow_info_a->hashval < flow_info_b->hashval) {
                return(-1);
            } else if (flow_info_a->hashval > flow_info_b->hashval) {
                return(1);
            }

            //Flows have the same hash
            if (flow_info_a->l4_protocol < flow_info_b->l4_protocol) {
                return(-1);
            } else if (flow_info_a->l4_protocol > flow_info_b->l4_protocol) {
                return(1);
            }

            //Flows have the same hash and lvl-4 protocol
            if (ip_tuples_equal(flow_info_a, flow_info_b) != 0 &&
                flow_info_a->src_port == flow_info_b->src_port &&
                flow_info_a->dst_port == flow_info_b->dst_port)
            {
                return(0);
            }

            //Comparing other infos like ip src and dst, ecc.
            return ip_tuples_compare(flow_info_a, flow_info_b);
        }


        static void ndpi_flow_info_freer(void * const node)
        /*
         * Frees infos about the flow of node
         */
        {
            auto * const flow = (nDPI_flow_info *)node;

            ndpi_free(flow->ndpi_dst);
            ndpi_free(flow->ndpi_src);
            ndpi_flow_free(flow->ndpi_flow);
            ndpi_free(flow);
        }


        static int ip_tuple_to_string(nDPI_flow_info const * const flow,
                                      char * const src_addr_str, size_t src_addr_len,
                                      char * const dst_addr_str, size_t dst_addr_len)
        /*
         * Converts the ip tuple into strings
         */
        {
            switch (flow->l3_type) {
                case L3_IP:
                    //IPv4
                    return inet_ntop(AF_INET, (struct sockaddr_in *)&flow->ip_tuple.v4.src,
                                     src_addr_str, src_addr_len) != nullptr &&
                           inet_ntop(AF_INET, (struct sockaddr_in *)&flow->ip_tuple.v4.dst,
                                     dst_addr_str, dst_addr_len) != nullptr;
                case L3_IP6:
                    //IPv6
                    return inet_ntop(AF_INET6, (struct sockaddr_in6 *)&flow->ip_tuple.v6.src[0],
                                     src_addr_str, src_addr_len) != nullptr &&
                           inet_ntop(AF_INET6, (struct sockaddr_in6 *)&flow->ip_tuple.v6.dst[0],
                                     dst_addr_str, dst_addr_len) != nullptr;
            }

            return 0;
        }
};