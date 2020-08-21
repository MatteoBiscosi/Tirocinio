#include "ndpi_light_includes.h"




/* ********************************** */

int NtDissector::DumpL4(FlowInfo& flow,
                        const uint8_t * & l4_ptr)
{
    if (flow.l4_protocol == IPPROTO_TCP) {
        /*  TCP   */
        const struct ndpi_tcphdr * tcp;

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

        udp = (struct ndpi_udphdr *)l4_ptr;
        flow.src_port = ntohs(udp->source);
        flow.dst_port = ntohs(udp->dest);

        this->captured_stats.udp_pkts++;
    }

    return 0;
}

/* ********************************** */

int NtDissector::DumpIPv4(FlowInfo& flow,
                            NtDyn1Descr_t* & pDyn1,
                            uint8_t* & packet,
                            const struct ndpi_ethhdr * & ethernet,
                            const struct ndpi_iphdr * & ip,
                            struct ndpi_ipv6hdr * & ip6,
                            const uint16_t & eth_offset,
                            uint16_t & ip_offset,
                            uint16_t & ip_size,
                            uint16_t & type,
                            const uint8_t * & l4_ptr,
                            uint16_t & l4_len)
{
    uint32_t ipaddr;
    struct IPv4Header_s *pl3 = (struct IPv4Header_s*)((uint8_t*)pDyn1 + pDyn1->descrLength + pDyn1->offset0);

    /*  Lvl 2   */
    ethernet = (struct ndpi_ethhdr *) &packet[eth_offset];
    ip_offset = sizeof(struct ndpi_ethhdr) + eth_offset;
    type = ntohs(ethernet->h_proto);

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

    /*  Lvl 3   */

    ip_size = pl3->ip_len;

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

    this->captured_stats.ip_pkts++;
    this->captured_stats.ip_bytes += (pl3->ip_len - 14);

    if(DumpL4(flow, l4_ptr) != 0)
        return -1;
    
    return 0;
}

/* ********************************** */

int NtDissector::DumpIPv6(FlowInfo& flow,
                            NtDyn1Descr_t* & pDyn1,
                            uint8_t* & packet,
                            const struct ndpi_ethhdr * & ethernet,
                            const struct ndpi_iphdr * & ip,
                            struct ndpi_ipv6hdr * & ip6,
                            const uint16_t & eth_offset,
                            uint16_t & ip_offset,
                            uint16_t & ip_size,
                            uint16_t & type,
                            const uint8_t * & l4_ptr,
                            uint16_t & l4_len)
{
    int i;
    struct IPv6Header_s *pl3 = (struct IPv6Header_s*)((uint8_t*)pDyn1 + pDyn1->descrLength + pDyn1->offset0);

    ethernet = (struct ndpi_ethhdr *) &packet[eth_offset];
    ip_offset = sizeof(struct ndpi_ethhdr) + eth_offset;
    type = ntohs(ethernet->h_proto);

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

    ip_size = pl3->ip_len;

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

    this->captured_stats.ip_pkts++;
    this->captured_stats.ip_bytes += pl3->ip_len;

    if(DumpL4(flow, l4_ptr) != 0)
        return -1;

    return 0;
}

/* ********************************** */


int NtDissector::getDyn(NtNetBuf_t& hNetBuffer,
                        FlowInfo& flow,
                        NtDyn1Descr_t* & pDyn1,
                        uint8_t* & packet,
                        const struct ndpi_ethhdr * & ethernet,
                        const struct ndpi_iphdr * & ip,
                        struct ndpi_ipv6hdr * & ip6,
                        const uint16_t & eth_offset,
                        uint16_t & ip_offset,
                        uint16_t & ip_size,
                        uint16_t & type,
                        const uint8_t * & l4_ptr,
                        uint16_t & l4_len)
{
    // descriptor DYN1 is used, which is set up via NTPL.
    pDyn1 = NT_NET_DESCR_PTR_DYN1(hNetBuffer);
    packet = reinterpret_cast<uint8_t*>(pDyn1) + pDyn1->descrLength;

    if (pDyn1->color & (1 << 6)) {
        tracer->traceEvent(1, "Packet contain an error and decoding cannot be trusted\n");
        return -1;
    } else {
        if (pDyn1->color & (1 << 5)) {
            tracer->traceEvent(1, "A non IPv4,IPv6 packet received\n");
            return -1;
        } else {
            switch (pDyn1->color >> 2) {
            case 0:  // IPv4
                    if(DumpIPv4(flow, pDyn1, packet, ethernet, ip, ip6, 
                                eth_offset, ip_offset, ip_size, type, l4_ptr, l4_len) != 0)
                        return -1;
                    break;
            case 1:  // IPv6
                    if(DumpIPv6(flow, pDyn1, packet, ethernet, ip, ip6, 
                                eth_offset, ip_offset, ip_size, type, l4_ptr, l4_len) != 0)
                        return -1;
                    break;
            case 2:  // Tunneled IPv4
                    if(DumpIPv4(flow, pDyn1, packet, ethernet, ip, ip6, 
                                eth_offset, ip_offset, ip_size, type, l4_ptr, l4_len) != 0)
                        return -1;
                    break;
            case 3:  // Tunneled IPv6
                    if(DumpIPv6(flow, pDyn1, packet, ethernet, ip, ip6, 
                                eth_offset, ip_offset, ip_size, type, l4_ptr, l4_len) != 0)
                        return -1;
                    break;
            }
        }
    }

    return 0;
}

/* ********************************** */

int NtDissector::searchVal(NapatechReader * & reader,
                            FlowInfo& flow,
                            void * & tree_result,
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

    hashed_index = flow.hashval % reader->getMaxActiveFlows();
    tree_result = ndpi_tfind(&flow, &reader->getActiveFlows()[hashed_index], ndpi_workflow_node_cmp);

    if(tree_result == nullptr)
        /*  Not Found   */
        return -1;
    else
        /*  Found   */
        return 0;
}

/* ********************************** */

int NtDissector::addVal(NapatechReader * & reader,
                        FlowInfo& flow,
                        FlowInfo * & flow_to_process,
                        size_t& hashed_index,
                        struct ndpi_id_struct * & ndpi_src,
                        struct ndpi_id_struct * & ndpi_dst)
{
    if(reader->newFlow(flow_to_process) != 0) 
        return -1;
    

    memcpy(flow_to_process, &flow, sizeof(*flow_to_process));
   // flow_to_process->flow_id = flow_id++;

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

    if (ndpi_tsearch(flow_to_process, &reader->getActiveFlows()[hashed_index], ndpi_workflow_node_cmp) == nullptr) {
        /* Possible Leak */
        return -1;  
    }

    ndpi_src = flow_to_process->ndpi_src;
    ndpi_dst = flow_to_process->ndpi_dst;
    
    return 0;
}

/* ********************************** */

void NtDissector::printFlowInfos(NapatechReader * & reader,
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
                ndpi_detection_giveup(reader->getNdpiStruct(),
                                      flow_to_process->ndpi_flow,
                                      1, &protocol_was_guessed);
        if (protocol_was_guessed != 0) {
            /*  Protocol guessed    */
            tracer->traceEvent(3, "\t[%8llu, %4d][GUESSED] protocol: %s | app protocol: %s | category: %s\n",
                    this->captured_stats.packets_captured,
                    flow_to_process->flow_id,
                    ndpi_get_proto_name(reader->getNdpiStruct(), flow_to_process->guessed_protocol.master_protocol),
                    ndpi_get_proto_name(reader->getNdpiStruct(), flow_to_process->guessed_protocol.app_protocol),
                    ndpi_category_get_name(reader->getNdpiStruct(), flow_to_process->guessed_protocol.category));
            
            this->captured_stats.protos_cnt[flow_to_process->guessed_protocol.master_protocol]++;
            this->captured_stats.guessed_flow_protocols++;

            char *tmp = ndpi_get_proto_breed_name(reader->getNdpiStruct(), ndpi_get_proto_breed(reader->getNdpiStruct(), flow_to_process->detected_l7_protocol.master_protocol));
            if(flow_to_process->l3_type == L3_IP) {
                if(strcmp(tmp, "Unsafe") == 0)
                    tracer->traceEvent(1, " [%s flow] src ip: %lu | port: %u\n", 
                                            tmp, flow_to_process->ip_tuple.v4.src, flow_to_process->dst_port);
                else
                    tracer->traceEvent(3, " [%s flow] src ip: %lu | port: %u\n", 
                                            tmp, flow_to_process->ip_tuple.v4.src, flow_to_process->dst_port);
            }
            else
            {
                if(strcmp(tmp, "Unsafe") == 0)
                    tracer->traceEvent(1, " [%s flow] src ip: %lu%lu | port: %u\n", 
                                            tmp, flow_to_process->ip_tuple.v6.src[0], flow_to_process->ip_tuple.v6.src[1], flow_to_process->dst_port);
                else
                    tracer->traceEvent(1, " [%s flow] src ip: %lu | port: %u\n", 
                                            tmp, flow_to_process->ip_tuple.v4.src, flow_to_process->dst_port);
            }
        } else {
            tracer->traceEvent(3, "\t[%8llu, %d, %4d][FLOW NOT CLASSIFIED]\n",
                                    this->captured_stats.packets_captured, flow_to_process->flow_id);
            this->captured_stats.unclassified_flow_protocols++;
        }
    }

    flow_to_process->detected_l7_protocol =
            ndpi_detection_process_packet(reader->getNdpiStruct(), flow_to_process->ndpi_flow,
                                          ip != nullptr ? (uint8_t *)ip : (uint8_t *)ip6,
                                          ip_size, time_ms, ndpi_src, ndpi_dst);

    if (ndpi_is_protocol_detected(reader->getNdpiStruct(),
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
                                    ndpi_get_proto_name(reader->getNdpiStruct(), flow_to_process->detected_l7_protocol.master_protocol),
                                    ndpi_get_proto_name(reader->getNdpiStruct(), flow_to_process->detected_l7_protocol.app_protocol),
                                    ndpi_category_get_name(reader->getNdpiStruct(), flow_to_process->detected_l7_protocol.category));
        }

        char *tmp = ndpi_get_proto_breed_name(reader->getNdpiStruct(), ndpi_get_proto_breed(reader->getNdpiStruct(), flow_to_process->detected_l7_protocol.master_protocol));
        if(flow_to_process->l3_type == L3_IP) {
            if(strcmp(tmp, "Unsafe") == 0)
                tracer->traceEvent(1, " [%s flow] src ip: %lu | port: %u\n", 
                                        tmp, flow_to_process->ip_tuple.v4.src, flow_to_process->dst_port);
            else
                tracer->traceEvent(3, " [%s flow] src ip: %lu | port: %u\n", 
                                        tmp, flow_to_process->ip_tuple.v4.src, flow_to_process->dst_port);
        }
        else
        {
            if(strcmp(tmp, "Unsafe") == 0)
                tracer->traceEvent(1, " [%s flow] src ip: %lu%lu | port: %u\n", 
                                        tmp, flow_to_process->ip_tuple.v6.src[0], flow_to_process->ip_tuple.v6.src[1], flow_to_process->dst_port);
            else
                tracer->traceEvent(1, " [%s flow] src ip: %lu | port: %u\n", 
                                        tmp, flow_to_process->ip_tuple.v4.src, flow_to_process->dst_port);
        }
    }
}

/* ********************************** */

void NtDissector::processPacket(void * args,
                                void * header_tmp,
                                void * stream_id_tmp)
{
    FlowInfo flow = FlowInfo();
    NapatechReader * reader = (NapatechReader *) args;

    NtNetBuf_t * hNetBuffer = ((NtNetBuf_t *) header_tmp);

    NtDyn1Descr_t* pDyn1;
    uint8_t* packet;

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

    // Updating time counters
    if(!this->captured_stats.nt_time_start)
    	this->captured_stats.nt_time_start = (uint64_t) NT_NET_GET_PKT_TIMESTAMP(* hNetBuffer);
    
    this->captured_stats.nt_time_end = (uint64_t) NT_NET_GET_PKT_TIMESTAMP(* hNetBuffer);
    
    // Checking idle flows
    reader->newPacket((void *)hNetBuffer);
    
    // Parsing packets
    this->getDyn(* hNetBuffer, flow, pDyn1, packet, ethernet, ip, ip6, 
		eth_offset, ip_offset, ip_size, type, l4_ptr, l4_len);
    
    this->captured_stats.packets_processed++;
    this->captured_stats.total_l4_data_len += l4_len;
    
    if(this->searchVal(reader, flow, tree_result, hashed_index) != 0) {
        if(this->addVal(reader, flow, flow_to_process, hashed_index, ndpi_src, ndpi_dst) != 0) {
            this->captured_stats.discarded_bytes += NT_NET_GET_PKT_CAP_LENGTH(* hNetBuffer);;
            reader->setNewFlow(false);
        }
        else {
            this->captured_stats.total_flows_captured++;
            reader->setNewFlow(true);
        }
    } else {
        reader->setNewFlow(false);
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
    if (flow_to_process->first_seen == 0) {
        flow_to_process->first_seen = time_ms;
    }
    flow_to_process->last_seen = time_ms;
    /* current packet is an TCP-ACK? */
    flow_to_process->flow_ack_seen = flow.flow_ack_seen;

    /* TCP-FIN: indicates that at least one side wants to end the connection */
    if (flow.flow_fin_ack_seen != 0 && flow_to_process->flow_fin_ack_seen == 0) {
        flow_to_process->flow_fin_ack_seen = 1;
        tracer->traceEvent(4, "[%8llu, %4u] end of flow\n",
                                    this->captured_stats.packets_captured, flow_to_process->flow_id);
        this->captured_stats.discarded_bytes += NT_NET_GET_PKT_CAP_LENGTH(* hNetBuffer);
        return;
    }
    
    this->printFlowInfos(reader, flow_to_process, ip, ip6, ip_size, ndpi_src, ndpi_dst, time_ms);
}

/* ********************************** */
