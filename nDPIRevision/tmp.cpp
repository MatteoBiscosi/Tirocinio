
static void ndpi_process_packet(uint8_t * const args,
                                struct pcap_pkthdr const * const header,
                                uint8_t const * const packet)
{
    struct nDPI_reader_thread * const reader_thread =
            (struct nDPI_reader_thread *)args;
    struct nDPI_workflow * workflow;
    struct nDPI_flow_info flow = {};

    size_t hashed_index;
    void * tree_result;
    struct nDPI_flow_info * flow_to_process;

    int direction_changed = 0;
    struct ndpi_id_struct * ndpi_src;
    struct ndpi_id_struct * ndpi_dst;

    const struct ndpi_ethhdr * ethernet;
    const struct ndpi_iphdr * ip;
    struct ndpi_ipv6hdr * ip6;

    uint64_t time_ms;
    const uint16_t eth_offset = 0;
    uint16_t ip_offset;
    uint16_t ip_size;

    const uint8_t * l4_ptr = NULL;
    uint16_t l4_len = 0;

    uint16_t type;
    int thread_index = INITIAL_THREAD_HASH; // generated with `dd if=/dev/random bs=1024 count=1 |& hd'

    if (reader_thread == NULL) {
        return;
    }
    workflow = reader_thread->workflow;

    if (workflow == NULL) {
        return;
    }

    workflow->packets_captured++;
    time_ms = ((uint64_t) header->ts.tv_sec) * TICK_RESOLUTION + header->ts.tv_usec / (1000000 / TICK_RESOLUTION);
    workflow->last_time = time_ms;


    /*  IS IT REALLY NEEDED TO CHECK FOR IDLE FLOWS EVERY PACKET????    */
    check_for_idle_flows(workflow);

    /* process datalink layer */
    switch (pcap_datalink(workflow->pcap_handle)) {
        case DLT_NULL:
            if (ntohl(*((uint32_t *)&packet[eth_offset])) == 0x00000002) {
                type = ETH_P_IP;
            } else {
                type = ETH_P_IPV6;
            }
            ip_offset = 4 + eth_offset;
            break;
        case DLT_EN10MB:
            if (header->len < sizeof(struct ndpi_ethhdr)) {
                fprintf(stderr, "[%8llu, %d] Ethernet packet too short - skipping\n",
                        workflow->packets_captured, reader_thread->array_index);
                return;
            }
            ethernet = (struct ndpi_ethhdr *) &packet[eth_offset];
            ip_offset = sizeof(struct ndpi_ethhdr) + eth_offset;
            type = ntohs(ethernet->h_proto);
            switch (type) {
                case ETH_P_IP: /* IPv4 */
                    if (header->len < sizeof(struct ndpi_ethhdr) + sizeof(struct ndpi_iphdr)) {
                        fprintf(stderr, "[%8llu, %d] IP packet too short - skipping\n",
                                workflow->packets_captured, reader_thread->array_index);
                        return;
                    }
                    break;
                case ETH_P_IPV6: /* IPV6 */
                    if (header->len < sizeof(struct ndpi_ethhdr) + sizeof(struct ndpi_ipv6hdr)) {
                        fprintf(stderr, "[%8llu, %d] IP6 packet too short - skipping\n",
                                workflow->packets_captured, reader_thread->array_index);
                        return;
                    }
                    break;
                case ETH_P_ARP: /* ARP */
                    return;
                default:
                    fprintf(stderr, "[%8llu, %d] Unknown Ethernet packet with type 0x%X - skipping\n",
                            workflow->packets_captured, reader_thread->array_index, type);
                    return;
            }
            break;
        default:
            fprintf(stderr, "[%8llu, %d] Captured non IP/Ethernet packet with datalink type 0x%X - skipping\n",
                    workflow->packets_captured, reader_thread->array_index, pcap_datalink(workflow->pcap_handle));
            return;
    }

    if (type == ETH_P_IP) {
        ip = (struct ndpi_iphdr *)&packet[ip_offset];
        ip6 = NULL;
    } else if (type == ETH_P_IPV6) {
        ip = NULL;
        ip6 = (struct ndpi_ipv6hdr *)&packet[ip_offset];
    } else {
        fprintf(stderr, "[%8llu, %d] Captured non IPv4/IPv6 packet with type 0x%X - skipping\n",
                workflow->packets_captured, reader_thread->array_index, type);
        return;
    }
    ip_size = header->len - ip_offset;

    if (type == ETH_P_IP && header->len >= ip_offset) {
        if (header->caplen < header->len) {
            fprintf(stderr, "[%8llu, %d] Captured packet size is smaller than packet size: %u < %u\n",
                    workflow->packets_captured, reader_thread->array_index, header->caplen, header->len);
        }
    }

    /* process layer3 e.g. IPv4 / IPv6 */
    if (ip != NULL && ip->version == 4) {
        if (ip_size < sizeof(*ip)) {
            fprintf(stderr, "[%8llu, %d] Packet smaller than IP4 header length: %u < %zu\n",
                    workflow->packets_captured, reader_thread->array_index, ip_size, sizeof(*ip));
            return;
        }

        flow.l3_type = L3_IP;
        if (ndpi_detection_get_l4((uint8_t*)ip, ip_size, &l4_ptr, &l4_len,
                                  &flow.l4_protocol, NDPI_DETECTION_ONLY_IPV4) != 0)
        {
            fprintf(stderr, "[%8llu, %d] nDPI IPv4/L4 payload detection failed, L4 length: %zu\n",
                    workflow->packets_captured, reader_thread->array_index, ip_size - sizeof(*ip));
            return;
        }

        flow.ip_tuple.v4.src = ip->saddr;
        flow.ip_tuple.v4.dst = ip->daddr;
        uint32_t min_addr = (flow.ip_tuple.v4.src > flow.ip_tuple.v4.dst ?
                             flow.ip_tuple.v4.dst : flow.ip_tuple.v4.src);
        thread_index = min_addr + ip->protocol;
    } else if (ip6 != NULL) {
        if (ip_size < sizeof(ip6->ip6_hdr)) {
            fprintf(stderr, "[%8llu, %d] Packet smaller than IP6 header length: %u < %zu\n",
                    workflow->packets_captured, reader_thread->array_index, ip_size, sizeof(ip6->ip6_hdr));
            return;
        }

        flow.l3_type = L3_IP6;
        if (ndpi_detection_get_l4((uint8_t*)ip6, ip_size, &l4_ptr, &l4_len,
                                  &flow.l4_protocol, NDPI_DETECTION_ONLY_IPV6) != 0)
        {
            fprintf(stderr, "[%8llu, %d] nDPI IPv6/L4 payload detection failed, L4 length: %zu\n",
                    workflow->packets_captured, reader_thread->array_index, ip_size - sizeof(*ip6));
            return;
        }

        flow.ip_tuple.v6.src[0] = ip6->ip6_src.u6_addr.u6_addr64[0];
        flow.ip_tuple.v6.src[1] = ip6->ip6_src.u6_addr.u6_addr64[1];
        flow.ip_tuple.v6.dst[0] = ip6->ip6_dst.u6_addr.u6_addr64[0];
        flow.ip_tuple.v6.dst[1] = ip6->ip6_dst.u6_addr.u6_addr64[1];
        uint64_t min_addr[2];
        if (flow.ip_tuple.v6.src[0] > flow.ip_tuple.v6.dst[0] &&
            flow.ip_tuple.v6.src[1] > flow.ip_tuple.v6.dst[1])
        {
            min_addr[0] = flow.ip_tuple.v6.dst[0];
            min_addr[1] = flow.ip_tuple.v6.dst[0];
        } else {
            min_addr[0] = flow.ip_tuple.v6.src[0];
            min_addr[1] = flow.ip_tuple.v6.src[0];
        }
        thread_index = min_addr[0] + min_addr[1] + ip6->ip6_hdr.ip6_un1_nxt;
    } else {
        fprintf(stderr, "[%8llu, %d] Non IP/IPv6 protocol detected: 0x%X\n",
                workflow->packets_captured, reader_thread->array_index, type);
        return;
    }

    /* process layer4 e.g. TCP / UDP */
    if (flow.l4_protocol == IPPROTO_TCP) {
        const struct ndpi_tcphdr * tcp;

        if (header->len < (l4_ptr - packet) + sizeof(struct ndpi_tcphdr)) {
            fprintf(stderr, "[%8llu, %d] Malformed TCP packet, packet size smaller than expected: %u < %zu\n",
                    workflow->packets_captured, reader_thread->array_index,
                    header->len, (l4_ptr - packet) + sizeof(struct ndpi_tcphdr));
            return;
        }
        tcp = (struct ndpi_tcphdr *)l4_ptr;
        flow.is_midstream_flow = (tcp->syn == 0 ? 1 : 0);
        flow.flow_fin_ack_seen = (tcp->fin == 1 && tcp->ack == 1 ? 1 : 0);
        flow.flow_ack_seen = tcp->ack;
        flow.src_port = ntohs(tcp->source);
        flow.dst_port = ntohs(tcp->dest);
    } else if (flow.l4_protocol == IPPROTO_UDP) {
        const struct ndpi_udphdr * udp;

        if (header->len < (l4_ptr - packet) + sizeof(struct ndpi_udphdr)) {
            fprintf(stderr, "[%8llu, %d] Malformed UDP packet, packet size smaller than expected: %u < %zu\n",
                    workflow->packets_captured, reader_thread->array_index,
                    header->len, (l4_ptr - packet) + sizeof(struct ndpi_udphdr));
            return;
        }
        udp = (struct ndpi_udphdr *)l4_ptr;
        flow.src_port = ntohs(udp->source);
        flow.dst_port = ntohs(udp->dest);
    }

    /* distribute flows to threads while keeping stability (same flow goes always to same thread) */
    thread_index += (flow.src_port < flow.dst_port ? flow.dst_port : flow.src_port);
    thread_index %= reader_thread_count;
    if (thread_index != reader_thread->array_index) {
        return;
    }
    workflow->packets_processed++;
    workflow->total_l4_data_len += l4_len;

#ifdef VERBOSE
    print_packet_info(reader_thread, header, l4_data_len, &flow);
#endif

    /* calculate flow hash for btree find, search(insert) */
    if (flow.l3_type == L3_IP) {
        if (ndpi_flowv4_flow_hash(flow.l4_protocol, flow.ip_tuple.v4.src, flow.ip_tuple.v4.dst,
                                  flow.src_port, flow.dst_port, 0, 0,
                                  (uint8_t *)&flow.hashval, sizeof(flow.hashval)) != 0)
        {
            flow.hashval = flow.ip_tuple.v4.src + flow.ip_tuple.v4.dst; // fallback
        }
    } else if (flow.l3_type == L3_IP6) {
        if (ndpi_flowv6_flow_hash(flow.l4_protocol, &ip6->ip6_src, &ip6->ip6_dst,
                                  flow.src_port, flow.dst_port, 0, 0,
                                  (uint8_t *)&flow.hashval, sizeof(flow.hashval)) != 0)
        {
            flow.hashval = flow.ip_tuple.v6.src[0] + flow.ip_tuple.v6.src[1];
            flow.hashval += flow.ip_tuple.v6.dst[0] + flow.ip_tuple.v6.dst[1];
        }
    }
    flow.hashval += flow.l4_protocol + flow.src_port + flow.dst_port;

    hashed_index = flow.hashval % workflow->max_active_flows;
    tree_result = ndpi_tfind(&flow, &workflow->ndpi_flows_active[hashed_index], ndpi_workflow_node_cmp);
    if (tree_result == NULL) {
        /* flow not found in btree: switch src <-> dst and try to find it again */
        uint64_t orig_src_ip[2] = { flow.ip_tuple.v6.src[0], flow.ip_tuple.v6.src[1] };
        uint64_t orig_dst_ip[2] = { flow.ip_tuple.v6.dst[0], flow.ip_tuple.v6.dst[1] };
        uint16_t orig_src_port = flow.src_port;
        uint16_t orig_dst_port = flow.dst_port;

        flow.ip_tuple.v6.src[0] = orig_dst_ip[0];
        flow.ip_tuple.v6.src[1] = orig_dst_ip[1];
        flow.ip_tuple.v6.dst[0] = orig_src_ip[0];
        flow.ip_tuple.v6.dst[1] = orig_src_ip[1];
        flow.src_port = orig_dst_port;
        flow.dst_port = orig_src_port;

        tree_result = ndpi_tfind(&flow, &workflow->ndpi_flows_active[hashed_index], ndpi_workflow_node_cmp);
        if (tree_result != NULL) {
            direction_changed = 1;
        }

        flow.ip_tuple.v6.src[0] = orig_src_ip[0];
        flow.ip_tuple.v6.src[1] = orig_src_ip[1];
        flow.ip_tuple.v6.dst[0] = orig_dst_ip[0];
        flow.ip_tuple.v6.dst[1] = orig_dst_ip[1];
        flow.src_port = orig_src_port;
        flow.dst_port = orig_dst_port;
    }

    if (tree_result == NULL) {
        /* flow still not found, must be new */
        if (workflow->cur_active_flows == workflow->max_active_flows) {
            fprintf(stderr, "[%8llu, %d] max flows to track reached: %llu, idle: %llu\n",
                    workflow->packets_captured, reader_thread->array_index,
                    workflow->max_active_flows, workflow->cur_idle_flows);
            return;
        }

        flow_to_process = (struct nDPI_flow_info *)ndpi_malloc(sizeof(*flow_to_process));
        if (flow_to_process == NULL) {
            fprintf(stderr, "[%8llu, %d] Not enough memory for flow info\n",
                    workflow->packets_captured, reader_thread->array_index);
            return;
        }

        workflow->cur_active_flows++;
        workflow->total_active_flows++;
        memcpy(flow_to_process, &flow, sizeof(*flow_to_process));
        flow_to_process->flow_id = flow_id++;

        flow_to_process->ndpi_flow = (struct ndpi_flow_struct *)ndpi_flow_malloc(SIZEOF_FLOW_STRUCT);
        if (flow_to_process->ndpi_flow == NULL) {
            fprintf(stderr, "[%8llu, %d, %4u] Not enough memory for flow struct\n",
                    workflow->packets_captured, reader_thread->array_index, flow_to_process->flow_id);
            return;
        }
        memset(flow_to_process->ndpi_flow, 0, SIZEOF_FLOW_STRUCT);

        flow_to_process->ndpi_src = (struct ndpi_id_struct *)ndpi_calloc(1, SIZEOF_ID_STRUCT);
        if (flow_to_process->ndpi_src == NULL) {
            fprintf(stderr, "[%8llu, %d, %4u] Not enough memory for src id struct\n",
                    workflow->packets_captured, reader_thread->array_index, flow_to_process->flow_id);
            return;
        }

        flow_to_process->ndpi_dst = (struct ndpi_id_struct *)ndpi_calloc(1, SIZEOF_ID_STRUCT);
        if (flow_to_process->ndpi_dst == NULL) {
            fprintf(stderr, "[%8llu, %d, %4u] Not enough memory for dst id struct\n",
                    workflow->packets_captured, reader_thread->array_index, flow_to_process->flow_id);
            return;
        }

        printf("[%8llu, %d, %4u] new %sflow\n", workflow->packets_captured, thread_index,
               flow_to_process->flow_id,
               (flow_to_process->is_midstream_flow != 0 ? "midstream-" : ""));
        if (ndpi_tsearch(flow_to_process, &workflow->ndpi_flows_active[hashed_index], ndpi_workflow_node_cmp) == NULL) {
            /* Possible Leak, but should not happen as we'd abort earlier. */
            return;
        }

        ndpi_src = flow_to_process->ndpi_src;
        ndpi_dst = flow_to_process->ndpi_dst;
    } else {
        flow_to_process = *(struct nDPI_flow_info **)tree_result;

        if (direction_changed != 0) {
            ndpi_src = flow_to_process->ndpi_dst;
            ndpi_dst = flow_to_process->ndpi_src;
        } else {
            ndpi_src = flow_to_process->ndpi_src;
            ndpi_dst = flow_to_process->ndpi_dst;
        }
    }

    flow_to_process->packets_processed++;
    flow_to_process->total_l4_data_len += l4_len;
    /* update timestamps, important for timeout handling */
    if (flow_to_process->first_seen == 0) {
        flow_to_process->first_seen = time_ms;
    }
    flow_to_process->last_seen = time_ms;
    /* current packet is an TCP-ACK? */
    flow_to_process->flow_ack_seen = flow.flow_ack_seen;

    /* TCP-FIN: indicates that at least one side wants to end the connection */
    if (flow.flow_fin_ack_seen != 0 && flow_to_process->flow_fin_ack_seen == 0) {
        flow_to_process->flow_fin_ack_seen = 1;
        printf("[%8llu, %d, %4u] end of flow\n",  workflow->packets_captured, thread_index,
               flow_to_process->flow_id);
        return;
    }

    /*
     * This example tries to use maximum supported packets for detection:
     * for uint8: 0xFF
     */
    if (flow_to_process->ndpi_flow->num_processed_pkts == 0xFF) {
        return;
    } else if (flow_to_process->ndpi_flow->num_processed_pkts == 0xFE) {
        /* last chance to guess something, better then nothing */
        uint8_t protocol_was_guessed = 0;
        flow_to_process->guessed_protocol =
                ndpi_detection_giveup(workflow->ndpi_struct,
                                      flow_to_process->ndpi_flow,
                                      1, &protocol_was_guessed);
        if (protocol_was_guessed != 0) {
            printf("[%8llu, %d, %4d][GUESSED] protocol: %s | app protocol: %s | category: %s\n",
                   workflow->packets_captured,
                   reader_thread->array_index,
                   flow_to_process->flow_id,
                   ndpi_get_proto_name(workflow->ndpi_struct, flow_to_process->guessed_protocol.master_protocol),
                   ndpi_get_proto_name(workflow->ndpi_struct, flow_to_process->guessed_protocol.app_protocol),
                   ndpi_category_get_name(workflow->ndpi_struct, flow_to_process->guessed_protocol.category));
        } else {
            printf("[%8llu, %d, %4d][FLOW NOT CLASSIFIED]\n",
                   workflow->packets_captured, reader_thread->array_index, flow_to_process->flow_id);
        }
    }

    flow_to_process->detected_l7_protocol =
            ndpi_detection_process_packet(workflow->ndpi_struct, flow_to_process->ndpi_flow,
                                          ip != NULL ? (uint8_t *)ip : (uint8_t *)ip6,
                                          ip_size, time_ms, ndpi_src, ndpi_dst);

    if (ndpi_is_protocol_detected(workflow->ndpi_struct,
                                  flow_to_process->detected_l7_protocol) != 0 &&
        flow_to_process->detection_completed == 0)
    {
        if (flow_to_process->detected_l7_protocol.master_protocol != NDPI_PROTOCOL_UNKNOWN ||
            flow_to_process->detected_l7_protocol.app_protocol != NDPI_PROTOCOL_UNKNOWN) {
            flow_to_process->detection_completed = 1;
            workflow->detected_flow_protocols++;
            printf("[%8llu, %d, %4d][DETECTED] protocol: %s | app protocol: %s | category: %s\n",
                   workflow->packets_captured,
                   reader_thread->array_index,
                   flow_to_process->flow_id,
                   ndpi_get_proto_name(workflow->ndpi_struct, flow_to_process->detected_l7_protocol.master_protocol),
                   ndpi_get_proto_name(workflow->ndpi_struct, flow_to_process->detected_l7_protocol.app_protocol),
                   ndpi_category_get_name(workflow->ndpi_struct, flow_to_process->detected_l7_protocol.category));
        }
    }

    if (flow_to_process->ndpi_flow->num_extra_packets_checked <
        flow_to_process->ndpi_flow->max_extra_packets_to_check)
    {
        /*
         * Your business logic starts here.
         *
         * This example does print some information about
         * TLS client and server hellos if available.
         *
         * You could also use nDPI's built-in json serialization
         * and send it to a high-level application for further processing.
         *
         * EoE - End of Example
         */

        if (flow_to_process->detected_l7_protocol.master_protocol == NDPI_PROTOCOL_TLS ||
            flow_to_process->detected_l7_protocol.app_protocol == NDPI_PROTOCOL_TLS)
        {
            if (flow_to_process->tls_client_hello_seen == 0 &&
                flow_to_process->ndpi_flow->l4.tcp.tls.hello_processed != 0)
            {
                uint8_t unknown_tls_version = 0;
                printf("[%8llu, %d, %4d][TLS-CLIENT-HELLO] version: %s | sni: %s | alpn: %s\n",
                       workflow->packets_captured,
                       reader_thread->array_index,
                       flow_to_process->flow_id,
                       ndpi_ssl_version2str(flow_to_process->ndpi_flow->protos.stun_ssl.ssl.ssl_version,
                                            &unknown_tls_version),
                       flow_to_process->ndpi_flow->protos.stun_ssl.ssl.client_requested_server_name,
                       (flow_to_process->ndpi_flow->protos.stun_ssl.ssl.alpn != NULL ?
                        flow_to_process->ndpi_flow->protos.stun_ssl.ssl.alpn : "-"));
                flow_to_process->tls_client_hello_seen = 1;
            }
            if (flow_to_process->tls_server_hello_seen == 0 &&
                flow_to_process->ndpi_flow->l4.tcp.tls.certificate_processed != 0)
            {
                uint8_t unknown_tls_version = 0;
                printf("[%8llu, %d, %4d][TLS-SERVER-HELLO] version: %s | common-name(s): %.*s | "
                       "issuer: %s | subject: %s\n",
                       workflow->packets_captured,
                       reader_thread->array_index,
                       flow_to_process->flow_id,
                       ndpi_ssl_version2str(flow_to_process->ndpi_flow->protos.stun_ssl.ssl.ssl_version,
                                            &unknown_tls_version),
                       flow_to_process->ndpi_flow->protos.stun_ssl.ssl.server_names_len,
                       flow_to_process->ndpi_flow->protos.stun_ssl.ssl.server_names,
                       (flow_to_process->ndpi_flow->protos.stun_ssl.ssl.issuerDN != NULL ?
                        flow_to_process->ndpi_flow->protos.stun_ssl.ssl.issuerDN : "-"),
                       (flow_to_process->ndpi_flow->protos.stun_ssl.ssl.subjectDN != NULL ?
                        flow_to_process->ndpi_flow->protos.stun_ssl.ssl.subjectDN : "-"));
                flow_to_process->tls_server_hello_seen = 1;
            }
        }
    }
}
