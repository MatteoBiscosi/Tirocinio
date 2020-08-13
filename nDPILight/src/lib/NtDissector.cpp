#include "ndpi_light_includes.h"




/* ********************************** */

void NtDissector::DumpL4(NtDyn1Descr_t * & pDyn1)
{
    printf("    %3d %8s | ", pDyn1->ipProtocol, pDyn1->ipProtocol == 6 ? "TCP" : pDyn1->ipProtocol == 17 ? "UDP" : "Other");
    if (pDyn1->ipProtocol == 6) {
      struct TCPHeader_s *pl4 = (struct TCPHeader_s*)((uint8_t*)pDyn1 + pDyn1->descrLength + pDyn1->offset1);
      printf("    %04X |      %04X | ", ntohs(pl4->tcp_src), ntohs(pl4->tcp_dest));
      printf("      %03X | ", (pl4->reserved & 1) << 8 | pl4->tcp_ec_ctl);
    } else if (pDyn1->ipProtocol == 17) {
      struct UDPHeader_s *pl4 = (struct UDPHeader_s*)((uint8_t*)pDyn1 + pDyn1->descrLength + pDyn1->offset1);
      printf("    %04d |      %04d | ", ntohs(pl4->udp_src), ntohs(pl4->udp_dest));
      printf("%9s | ", "N/A");
    } else {
      printf("%8s %9s | ", " ", " ");
      printf("%9s | ", " ");
    }
    printf("%8d bytes\n", pDyn1->capLength - 4 - pDyn1->descrLength - pDyn1->offset0);
}

/* ********************************** */

void NtDissector::DumpIPv4(NtDyn1Descr_t * & pDyn1)
{
    uint32_t ipaddr;
    struct IPv4Header_s *pl3 = (struct IPv4Header_s*)((uint8_t*)pDyn1 + pDyn1->descrLength + pDyn1->offset0);
    printf("%-16s | %-15s - %-15s | %-16s | %-8s | %-9s | %-9s | %-8s\n", "Time", "Src", "Dest", "Protocol", "Src port", "Dest port", "TCP flags", "Bytes");
    printf("%16llu | ", pDyn1->timestamp);
    ipaddr = ntohl(pl3->ip_src);
    printf("%03d.%03d.%03d.%03d - ", (ipaddr >> 24) & 0xFF, (ipaddr >> 16) & 0xFF, (ipaddr >> 8) & 0xFF, ipaddr & 0xFF);
    ipaddr = ntohl(pl3->ip_dest);
    printf("%03d.%03d.%03d.%03d | ", (ipaddr >> 24) & 0xFF, (ipaddr >> 16) & 0xFF, (ipaddr >> 8) & 0xFF, ipaddr & 0xFF);
    DumpL4(pDyn1);
}

/* ********************************** */

void NtDissector::DumpIPv6(NtDyn1Descr_t * & pDyn1)
{
    int i;
    struct IPv6Header_s *pl3 = (struct IPv6Header_s*)((uint8_t*)pDyn1 + pDyn1->descrLength + pDyn1->offset0);
    printf("%-16s | %-32s - %-32s | %-16s | %-8s | %-9s | %-9s | %-8s\n", "Time", "Src", "Dest", "Protocol", "Src port", "Dest port", "TCP flags", "Bytes");
    printf("%16" PRIx64 " | ", pDyn1->timestamp);
    for(i=0; i < 16; i++) {
      printf("%02x", *(((uint8_t*)&pl3->ip_src)+i));
    }
    printf(" - ");
    for(i=0; i < 16; i++) {
      printf("%02x", *(((uint8_t*)&pl3->ip_dest)+i));
    }
    printf(" | ");
    DumpL4(pDyn1);
}

/* ********************************** */

void NtDissector::getDyn(NtNetBuf_t& hNetBuffer)
{
    // descriptor DYN1 is used, which is set up via NTPL.
    this->pDyn1 = NT_NET_DESCR_PTR_DYN1(hNetBuffer);
    this->packet = reinterpret_cast<uint8_t*>(pDyn1) + pDyn1->descrLength;

    if (pDyn1->color & (1 << 6)) {
        tracer->traceEvent(1, "Packet contain an error and decoding cannot be trusted\n");
    } else {
        if (pDyn1->color & (1 << 5)) {
            tracer->traceEvent(1, "A non IPv4,IPv6 packet received\n");
        } else {
            switch (pDyn1->color >> 2) {
            case 0:  // IPv4
                    DumpIPv4(pDyn1);
                    break;
            case 1:  // IPv6
                    DumpIPv6(pDyn1);
                    break;
            case 2:  // Tunneled IPv4
                    DumpIPv4(pDyn1);
                    break;
            case 3:  // Tunneled IPv6
                    DumpIPv6(pDyn1);
                    break;
            }
        }
    }
}

/* ********************************** */

int PcapDissector::processL2(Reader * const reader,
                                NtNetBuf_t& hNetBuffer,
                                uint16_t& type,
                                uint16_t& ip_size,
                                uint16_t& ip_offset,
                                const uint16_t& eth_offset,
                                const struct ndpi_ethhdr * & ethernet)
{
    if (this->pDyn1->capLenght < sizeof(struct ndpi_ethhdr)) {
        tracer->traceEvent(1, "[%8llu] Ethernet packet too short - skipping\n", this->captured_stats.packets_captured);
        return -1;
    }

    ethernet = (struct ndpi_ethhdr *) &(this->packet)[eth_offset];
    ip_offset = sizeof(struct ndpi_ethhdr) + eth_offset;
    type = ntohs(ethernet->h_proto);
    switch (type) {
        case ETH_P_IP:
            /* IPv4 */
            if (this->pDyn1->capLenght < sizeof(struct ndpi_ethhdr) + sizeof(struct ndpi_iphdr)) {
                tracer->traceEvent(1, "[%8llu] Ethernet packet too short - skipping\n", this->captured_stats.packets_captured);
                return -1;
            }
            break;

        case ETH_P_IPV6:
            /* IPV6 */
            if (this->pDyn1->capLenght < sizeof(struct ndpi_ethhdr) + sizeof(struct ndpi_ipv6hdr)) {
                tracer->traceEvent(1, "[%8llu] Ethernet packet too short - skipping\n", this->captured_stats.packets_captured);
                return -1;
            }
            break;

        case ETH_P_ARP:
            /* ARP */
            return -1;

        default:
            tracer->traceEvent(1, "[%8llu] Unknown Ethernet packet with type 0x%X - skipping\n", 
                                this->captured_stats.packets_captured, type);
            return -1;
    }

    return 0;
}

/* ********************************** */

int PcapDissector::setL2Ip(pcap_pkthdr const * const header,
                            uint8_t const * const packet,
                            uint16_t& type,
                            uint16_t& ip_size,
                            uint16_t& ip_offset,
                            const struct ndpi_iphdr * & ip,
                            struct ndpi_ipv6hdr * & ip6)
{
    if (type == ETH_P_IP) {
        ip = (struct ndpi_iphdr *)&packet[ip_offset];
        ip6 = nullptr;
    } else if (type == ETH_P_IPV6) {
        ip = nullptr;
        ip6 = (struct ndpi_ipv6hdr *)&packet[ip_offset];
    } else {
        tracer->traceEvent(1, "[%8llu] Captured non IPv4/IPv6 packet with type 0x%X - skipping\n",
                            this->captured_stats.packets_captured, type); 
        return -1;
    }

    ip_size = this->pDyn1->descrLength - ip_offset;

    if (type == ETH_P_IP && this->pDyn1->capLenght >= ip_offset) {
        if (this->pDyn1->capLenght < header->len) {
            tracer->traceEvent(0, "[%8llu] Captured packet size is smaller than packet size: %u < %u\n", 
                                    this->captured_stats.packets_captured, header->caplen, header->len); 
            return -1;
        }
    }

    return 0;
}

/* ********************************** */

int PcapDissector::processL3(FlowInfo& flow,
                          pcap_pkthdr const * const header,
                          uint8_t const * const packet,
                          uint16_t& type,
                          uint16_t& ip_size,
                          uint16_t& ip_offset,
                          const struct ndpi_iphdr * & ip,
                          struct ndpi_ipv6hdr * & ip6,
                          const uint8_t * & l4_ptr,
                          uint16_t& l4_len)
{
    if (ip != nullptr && ip->version == 4) {
        /*  IPv4    */
        if (ip_size < sizeof(*ip)) {
            tracer->traceEvent(0, "[%8llu] Packet smaller than IP4 header length: %u < %zu\n", 
                                    this->captured_stats.packets_captured, ip_size, sizeof(*ip)); 
            return -1;
        }

        flow.setFlowL3Type(4);

        if (ndpi_detection_get_l4((uint8_t*)ip, ip_size, &l4_ptr, &l4_len,
                                  &flow.l4_protocol, NDPI_DETECTION_ONLY_IPV4) != 0)
        {

            tracer->traceEvent(0, "[%8llu] nDPI IPv4/L4 payload detection failed, L4 length: %zu\n",
                                    this->captured_stats.packets_captured, ip_size - sizeof(*ip));
            return -1;
        }

        flow.ip_tuple.v4.src = ip->saddr;
        flow.ip_tuple.v4.dst = ip->daddr;

    } else if (ip6 != nullptr) {
        /*  IPv6    */
        if (ip_size < sizeof(ip6->ip6_hdr)) {
            tracer->traceEvent(0, "[%8llu] Packet smaller than IP6 header length: %u < %zu\n",
                                    this->captured_stats.packets_captured, ip_size, sizeof(ip6->ip6_hdr));
            return -1;
        }

        flow.setFlowL3Type(6);

        if (ndpi_detection_get_l4((uint8_t*)ip6, ip_size, &l4_ptr, &l4_len,
                                  &flow.l4_protocol, NDPI_DETECTION_ONLY_IPV6) != 0)
        {   
            tracer->traceEvent(0, "[%8llu] nDPI IPv6/L4 payload detection failed, L4 length: %zu\n",
                                    this->captured_stats.packets_captured, ip_size - sizeof(*ip));
            return -1;
        }

        flow.ip_tuple.v6.src[0] = ip6->ip6_src.u6_addr.u6_addr64[0];
        flow.ip_tuple.v6.src[1] = ip6->ip6_src.u6_addr.u6_addr64[1];
        flow.ip_tuple.v6.dst[0] = ip6->ip6_dst.u6_addr.u6_addr64[0];
        flow.ip_tuple.v6.dst[1] = ip6->ip6_dst.u6_addr.u6_addr64[1];
    } else {
        tracer->traceEvent(0, "[%8llu] Non IP/IPv6 protocol detected: 0x%X\n",
                                this->captured_stats.packets_captured, type);
        return -1;
    }

    this->captured_stats.ip_pkts++;
    this->captured_stats.ip_bytes += (header->len - 14);

    return 0;
}

/* ********************************** */

int PcapDissector::processL4(FlowInfo& flow,
                          pcap_pkthdr const * const header,
                          uint8_t const * const packet,
                          const uint8_t * & l4_ptr,
                          uint16_t& l4_len)
{
    if (flow.l4_protocol == IPPROTO_TCP) {
        /*  TCP   */
        const struct ndpi_tcphdr * tcp;

        if (header->len < (l4_ptr - packet) + sizeof(struct ndpi_tcphdr)) {
            tracer->traceEvent(0, "[%8llu] Malformed TCP packet, packet size smaller than expected: %u < %zu\n",
                                this->captured_stats.packets_captured, header->len, (l4_ptr - packet) + sizeof(struct ndpi_tcphdr));
            return -1;
        }

        tcp = (struct ndpi_tcphdr *)l4_ptr;

        /*  Checks the state of the flow */
        flow.is_midstream_flow = (tcp->syn == 0 ? 1 : 0);
        flow.flow_fin_ack_seen = (tcp->fin == 1 && tcp->ack == 1 ? 1 : 0);
        flow.flow_ack_seen = tcp->ack;
        flow.src_port = ntohs(tcp->source);
        flow.dst_port = ntohs(tcp->dest);

        this->captured_stats.tcp_pkts++;

    } else if (flow.l4_protocol == IPPROTO_UDP) {
        /*  UDP   */
        const struct ndpi_udphdr * udp;

        if (header->len < (l4_ptr - packet) + sizeof(struct ndpi_udphdr)) {
            tracer->traceEvent(0, "[%8llu] Malformed UDP packet, packet size smaller than expected: %u < %zu\n",
                                this->captured_stats.packets_captured, header->len, (l4_ptr - packet) + sizeof(struct ndpi_udphdr));
            return -1;
        }
        udp = (struct ndpi_udphdr *)l4_ptr;
        flow.src_port = ntohs(udp->source);
        flow.dst_port = ntohs(udp->dest);

        this->captured_stats.udp_pkts++;
    }

    return 0;
}

/* ********************************** */

int PcapDissector::searchVal(Reader * & reader,
                          FlowInfo& flow,
                          void * & tree_result,
                          struct ndpi_ipv6hdr * & ip6,
                          size_t& hashed_index)
{
    if (flow.getFlowL3Type() == 4) {
        /*  IPv4    */
        flow.hashval = flow.ip_tuple.v4.src + flow.ip_tuple.v4.dst;
    } else if (flow.getFlowL3Type() == 6) {
        /*  IPv6    */
        flow.hashval = flow.ip_tuple.v6.src[0] + flow.ip_tuple.v6.src[1];
        flow.hashval += flow.ip_tuple.v6.dst[0] + flow.ip_tuple.v6.dst[1];
    }
    flow.hashval += flow.l4_protocol + flow.src_port + flow.dst_port;

    hashed_index = flow.hashval % reader->max_active_flows;
    tree_result = ndpi_tfind(&flow, &reader->ndpi_flows_active[hashed_index], ndpi_workflow_node_cmp);

    if(tree_result == nullptr)
        /*  Not Found   */
        return -1;
    else
        /*  Found   */
        return 0;
}

/* ********************************** */

int PcapDissector::addVal(Reader * & reader,
                            FlowInfo& flow,
                            FlowInfo * & flow_to_process,
                            size_t& hashed_index,
                            struct ndpi_id_struct * & ndpi_src,
                            struct ndpi_id_struct * & ndpi_dst)
{
    /* flow still not found, must be new */
    if(reader->newFlow(flow_to_process) != 0) 
        return -1;
    

    memcpy(flow_to_process, &flow, sizeof(*flow_to_process));
    flow_to_process->flow_id = flow_id++;

    flow_to_process->ndpi_flow = (struct ndpi_flow_struct *)ndpi_flow_malloc(SIZEOF_FLOW_STRUCT);
    if (flow_to_process->ndpi_flow == nullptr) {
        tracer->traceEvent(0, "[%8llu, %4u] Not enough memory for flow struct\n",
                                this->captured_stats.packets_captured, flow_to_process->flow_id);
        return -1;
    }

    memset(flow_to_process->ndpi_flow, 0, SIZEOF_FLOW_STRUCT);

    flow_to_process->ndpi_src = (struct ndpi_id_struct *)ndpi_calloc(1, SIZEOF_ID_STRUCT);
    if (flow_to_process->ndpi_src == nullptr) {
        tracer->traceEvent(0, "[%8llu, %4u] Not enough memory for src id struct\n",
                                this->captured_stats.packets_captured, flow_to_process->flow_id);
        return -1;
    }

    flow_to_process->ndpi_dst = (struct ndpi_id_struct *)ndpi_calloc(1, SIZEOF_ID_STRUCT);
    if (flow_to_process->ndpi_dst == nullptr) {
        tracer->traceEvent(0, "[%8llu, %4u] Not enough memory for dst id struct\n",
                                this->captured_stats.packets_captured, flow_to_process->flow_id);
        return -1;
    }

    
    tracer->traceEvent(4, "[%8llu, %4u] new %sflow\n", this->captured_stats.packets_captured, 
                            flow_to_process->flow_id, (flow_to_process->is_midstream_flow != 0 ? "midstream-" : ""));

    if (ndpi_tsearch(flow_to_process, &reader->ndpi_flows_active[hashed_index], ndpi_workflow_node_cmp) == nullptr) {
        /* Possible Leak */
        return -1;  
    }

    ndpi_src = flow_to_process->ndpi_src;
    ndpi_dst = flow_to_process->ndpi_dst;

    return 0;
}

/* ********************************** */

void PcapDissector::printFlowInfos(Reader * & reader,
                                    FlowInfo * & flow_to_process,
                                    const struct ndpi_iphdr * & ip,
                                    struct ndpi_ipv6hdr * & ip6,
                                    uint16_t& ip_size,
                                    struct ndpi_id_struct * & ndpi_src,
                                    struct ndpi_id_struct * & ndpi_dst,
                                    uint64_t& time_ms)
{
    if (flow_to_process->ndpi_flow->num_processed_pkts == 0xFF) {
        return;
    } else if (flow_to_process->ndpi_flow->num_processed_pkts == 0xFE) {
        /* last chance to guess something, better then nothing */
        uint8_t protocol_was_guessed = 0;
        flow_to_process->guessed_protocol =
                ndpi_detection_giveup(reader->ndpi_struct,
                                      flow_to_process->ndpi_flow,
                                      1, &protocol_was_guessed);
        if (protocol_was_guessed != 0) {
            /*  Protocol guessed    */
            tracer->traceEvent(3, "\t[%8llu, %4d][GUESSED] protocol: %s | app protocol: %s | category: %s\n",
                    this->captured_stats.packets_captured,
                    flow_to_process->flow_id,
                    ndpi_get_proto_name(reader->ndpi_struct, flow_to_process->guessed_protocol.master_protocol),
                    ndpi_get_proto_name(reader->ndpi_struct, flow_to_process->guessed_protocol.app_protocol),
                    ndpi_category_get_name(reader->ndpi_struct, flow_to_process->guessed_protocol.category));
            
            this->captured_stats.protos_cnt[flow_to_process->guessed_protocol.master_protocol]++;
            this->captured_stats.guessed_flow_protocols++;
        } else {
            tracer->traceEvent(3, "\t[%8llu, %d, %4d][FLOW NOT CLASSIFIED]\n",
                                    this->captured_stats.packets_captured, flow_to_process->flow_id);
            this->captured_stats.unclassified_flow_protocols++;
        }
    }

    flow_to_process->detected_l7_protocol =
            ndpi_detection_process_packet(reader->ndpi_struct, flow_to_process->ndpi_flow,
                                          ip != nullptr ? (uint8_t *)ip : (uint8_t *)ip6,
                                          ip_size, time_ms, ndpi_src, ndpi_dst);

    if (ndpi_is_protocol_detected(reader->ndpi_struct,
                                  flow_to_process->detected_l7_protocol) != 0 &&
        flow_to_process->detection_completed == 0)
    {
        if (flow_to_process->detected_l7_protocol.master_protocol != NDPI_PROTOCOL_UNKNOWN ||
            flow_to_process->detected_l7_protocol.app_protocol != NDPI_PROTOCOL_UNKNOWN) {
            //Protocol detected
            this->captured_stats.protos_cnt[flow_to_process->detected_l7_protocol.master_protocol]++;
            flow_to_process->detection_completed = 1;
            this->captured_stats.detected_flow_protocols++;
            tracer->traceEvent(3, "\t[%8llu, %4d][DETECTED] protocol: %s | app protocol: %s | category: %s\n",
                                    this->captured_stats.packets_captured,
                                    flow_to_process->flow_id,
                                    ndpi_get_proto_name(reader->ndpi_struct, flow_to_process->detected_l7_protocol.master_protocol),
                                    ndpi_get_proto_name(reader->ndpi_struct, flow_to_process->detected_l7_protocol.app_protocol),
                                    ndpi_category_get_name(reader->ndpi_struct, flow_to_process->detected_l7_protocol.category));
        }
    }
}

/* ********************************** */

void NtDissector::processPacket(void * args,
                                    void * header_tmp,
                                    void * packet)
{
    FlowInfo flow = FlowInfo();
    Reader * reader = (Reader *) args;
    
    NtNetBuf_t * hNetBuffer = ((NtNetBuf_t *) header_tmp);

    size_t hashed_index = 0;
    void * tree_result = nullptr;
    FlowInfo * flow_to_process = nullptr;

    struct ndpi_id_struct * ndpi_src = nullptr;
    struct ndpi_id_struct * ndpi_dst = nullptr;

    const struct ndpi_ethhdr * ethernet = nullptr;
    const struct ndpi_iphdr * ip = nullptr;
    struct ndpi_ipv6hdr * ip6 = nullptr;

    uint64_t time_ms = 0;
    const uint16_t eth_offset = 0;
    uint16_t ip_offset = 0;
    uint16_t ip_size = 0;
    uint16_t type = 0;

    const uint8_t * l4_ptr = nullptr;
    uint16_t l4_len = 0;

    this->captured_stats.packets_captured++;

    if(!this->captured_stats.nt_time_start)
    	this->captured_stats.nt_time_start = (uint64_t) NT_NET_GET_PKT_TIMESTAMP(* hNetBuffer);

    this->captured_stats.nt_time_end = (uint64_t) NT_NET_GET_PKT_TIMESTAMP(* hNetBuffer);
    
    reader->newPacket((void *)hNetBuffer);

    std::cout << "Prova 3\n";

    tracer->traceEvent(2, "Packet received;\tPacket number: %3llu\n", this->captured_stats.packets_captured);

    this->getDyn(* hNetBuffer);

    std::cout << "Prova 4\n";
    pkt_parser->captured_stats.packets_processed++;
    pkt_parser->captured_stats.total_l4_data_len += l4_len;

    /*
    if(this->searchVal(reader, flow, tree_result, ip6, hashed_index) != 0) {
        if(this->addVal(reader, flow, flow_to_process, hashed_index, ndpi_src, ndpi_dst) != 0) {
            this->captured_stats.discarded_bytes += header->len;
            return;
        }
        else
            this->captured_stats.total_flows_captured++;
    } else {
        flow_to_process = *(FlowInfo **)tree_result;

        if (ndpi_src != flow_to_process->ndpi_src) {
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
    /*if (flow_to_process->first_seen == 0) {
        flow_to_process->first_seen = time_ms;
    }
    flow_to_process->last_seen = time_ms;
    /* current packet is an TCP-ACK? */
    //flow_to_process->flow_ack_seen = flow.flow_ack_seen;

    /* TCP-FIN: indicates that at least one side wants to end the connection */
    /*if (flow.flow_fin_ack_seen != 0 && flow_to_process->flow_fin_ack_seen == 0) {
        flow_to_process->flow_fin_ack_seen = 1;
        tracer->traceEvent(4, "[%8llu, %4u] end of flow\n",
                                    this->captured_stats.packets_captured, flow_to_process->flow_id);
        this->captured_stats.discarded_bytes += header->len;
        return;
    }

    this->printFlowInfos(reader, flow_to_process, ip, ip6, ip_size, ndpi_src, ndpi_dst, time_ms);
*/}

/* ********************************** */
