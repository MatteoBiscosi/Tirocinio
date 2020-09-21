#include "ndpi_light_includes.h"

#include "Profiling.h"


/* ********************************** */

void NtDissector::printBriefInfos(Reader *reader)
{
    NtStatistics_t hStat;
    uint64_t delta = 0;
    NapatechReader *reader_tmp = (NapatechReader *) reader;
    
    // Open the stat stream.
    hStat.cmd = NT_STATISTICS_READ_CMD_QUERY_V3;
    hStat.u.query_v3.poll = 0;
    hStat.u.query_v3.clear = 1;
    NT_StatRead(*reader_tmp->getStatStream(), &hStat);
    
    this->captured_stats.packets_captured = (long long unsigned int)hStat.u.query_v3.data.port.aPorts[0].rx.extDrop.pktsFilterDrop + 
                                            (long long unsigned int)hStat.u.query_v3.data.port.aPorts[1].rx.extDrop.pktsFilterDrop +
                                            this->captured_stats.packets_captured;
    this->captured_stats.total_wire_bytes = (long long unsigned int)hStat.u.query_v3.data.port.aPorts[0].rx.extDrop.octetsFilterDrop + 
                                            (long long unsigned int)hStat.u.query_v3.data.port.aPorts[1].rx.extDrop.octetsFilterDrop +
                                            this->captured_stats.total_wire_bytes;

    delta = this->captured_stats.packets_captured - this->captured_stats.previous_packets;
    this->captured_stats.previous_packets = this->captured_stats.packets_captured;

    tracer->traceEvent(2, "\tCapture brief summary: Tot. packets: %llu | Tot. bytes: %llu | pps: %llu\r\n",
                                this->captured_stats.packets_captured, this->captured_stats.total_wire_bytes, delta);
}

/* ********************************** */

int NtDissector::parsePacket(KeyInfo & key,
                                FlowInfo & flow,
                                Reader * & args,
                                void * header_tmp,
                                void * packet_tmp,
                                PacketInfo & pkt_infos)
{
    NapatechReader * reader = (NapatechReader *) args;
    NtNetBuf_t * hNetBuffer = ((NtNetBuf_t *) header_tmp);
    NtDyn1Descr_t* pDyn1;
    
    // Updating time counters
    pkt_infos.time_ms = NT_NET_GET_PKT_TIMESTAMP(* hNetBuffer);
    pkt_infos.eth_offset = 0;

    // Checking idle flows
    reader->newPacket((void *)hNetBuffer);  

    // Parsing packets
    // descriptor DYN1 is used, which is set up via NTPL.
    pDyn1 = NT_NET_GET_PKT_DESCR_PTR_DYN1(* hNetBuffer);
    uint8_t* packet = (uint8_t *) NT_NET_GET_PKT_L2_PTR(* hNetBuffer);

    switch (pDyn1->color >> 2) {
    case 0: {  // IPv4
        pkt_infos.ethernet = (struct ndpi_ethhdr *) &packet[pkt_infos.eth_offset];
        pkt_infos.ip_offset = sizeof(struct ndpi_ethhdr) + pkt_infos.eth_offset;
        pkt_infos.ip = (struct ndpi_iphdr *)(&packet[pkt_infos.ip_offset]);
        pkt_infos.ip6 = nullptr;
        pkt_infos.ip_size = pDyn1->capLength - pDyn1->descrLength - pkt_infos.ip_offset;

        flow.setFlowL3Type(4);   

        pkt_infos.l4_ptr = &packet[pDyn1->offset1];

        /* Analyse lvl 4 */
        if (pDyn1->ipProtocol == 6) {
            /*  TCP   */
            const struct ndpi_tcphdr * tcp;
            flow.l4_protocol = IPPROTO_TCP;

            tcp = (struct ndpi_tcphdr *)pkt_infos.l4_ptr;

            flow.src_port = ntohs(tcp->source);
            flow.dst_port = ntohs(tcp->dest);
            key.src_port = ntohs(tcp->source);
            key.dst_port = ntohs(tcp->dest);

            this->captured_stats.tcp_pkts++;
        } else {
            /*  UDP   */
            const struct ndpi_udphdr * udp;
            flow.l4_protocol = IPPROTO_UDP;

            udp = (struct ndpi_udphdr *)pkt_infos.l4_ptr;

            flow.src_port = ntohs(udp->source);
            flow.dst_port = ntohs(udp->dest);
            key.src_port = ntohs(udp->source);
            key.dst_port = ntohs(udp->dest);

            this->captured_stats.udp_pkts++;
        }

        
	    flow.ip_tuple.v4.src = pkt_infos.ip->saddr;
        flow.ip_tuple.v4.dst = pkt_infos.ip->daddr;

        key.l3_type = L3_IP;

        key.ip_tuple.v4.src = pkt_infos.ip->saddr;
        key.ip_tuple.v4.dst = pkt_infos.ip->daddr;

        key.hashval = flow.ip_tuple.v4.src + flow.ip_tuple.v4.dst + flow.l4_protocol + flow.src_port + flow.dst_port;
	flow.hashval = key.hashval;
        pkt_infos.tree_result = reader->getActiveFlows()->find(flow);
        //flow.hashval += flow.l4_protocol + flow.src_port + flow.dst_port;

        //pkt_infos.hashed_index = (uint64_t) flow.hashval % reader->getMaxActiveFlows();
        //pkt_infos.tree_result = ndpi_tfind(&flow, &reader->getActiveFlows()[pkt_infos.hashed_index], ndpi_workflow_node_cmp);
	//PROFILING_SECTION_ENTER("Searching flow", 6 /* section id */);
        //pkt_infos.tree_result = reader->getActiveFlows()->find(key);
	//PROFILING_SECTION_EXIT(6 /* section id */);

        this->captured_stats.ip_pkts++;
        this->captured_stats.ip_bytes += pkt_infos.ip_size;

        return 0;
    }	
    case 1: { // IPv6
        /*  Lvl 2   */
        pkt_infos.ethernet = (struct ndpi_ethhdr *) &packet[pkt_infos.eth_offset];
        pkt_infos.ip_offset = sizeof(struct ndpi_ethhdr) + pkt_infos.eth_offset;
        pkt_infos.ip = nullptr;
        pkt_infos.ip6 = (struct ndpi_ipv6hdr *)&packet[pkt_infos.ip_offset];

        pkt_infos.ip_size = pDyn1->capLength - pDyn1->descrLength - pkt_infos.ip_offset;

        flow.setFlowL3Type(6);   

        /* Analyse lvl 4 */
        if (pDyn1->ipProtocol == 6) {
            /*  TCP   */ 
            const struct ndpi_tcphdr * tcp;
            flow.l4_protocol = IPPROTO_TCP;

            tcp = (struct ndpi_tcphdr *)pkt_infos.l4_ptr;

            flow.src_port = ntohs(tcp->source);
            flow.dst_port = ntohs(tcp->dest);
            key.src_port = ntohs(tcp->source);
            key.dst_port = ntohs(tcp->dest);

            this->captured_stats.tcp_pkts++;
        } else {
            /*  UDP   */
            const struct ndpi_udphdr * udp;
            flow.l4_protocol = IPPROTO_UDP;

            udp = (struct ndpi_udphdr *)pkt_infos.l4_ptr;

            flow.src_port = ntohs(udp->source);
            flow.dst_port = ntohs(udp->dest);
            key.src_port = ntohs(udp->source);
            key.dst_port = ntohs(udp->dest);

            this->captured_stats.udp_pkts++;
        }
        
        flow.ip_tuple.v6.src[0] = pkt_infos.ip6->ip6_src.u6_addr.u6_addr64[0];
        flow.ip_tuple.v6.src[1] = pkt_infos.ip6->ip6_src.u6_addr.u6_addr64[1];
        flow.ip_tuple.v6.dst[0] = pkt_infos.ip6->ip6_dst.u6_addr.u6_addr64[0];
        flow.ip_tuple.v6.dst[1] = pkt_infos.ip6->ip6_dst.u6_addr.u6_addr64[1];

        key.l3_type = L3_IP6;

        key.ip_tuple.v6.src[0] = pkt_infos.ip6->ip6_src.u6_addr.u6_addr64[0];
        key.ip_tuple.v6.src[1] = pkt_infos.ip6->ip6_src.u6_addr.u6_addr64[1];
        key.ip_tuple.v6.dst[0] = pkt_infos.ip6->ip6_dst.u6_addr.u6_addr64[0];
        key.ip_tuple.v6.dst[1] = pkt_infos.ip6->ip6_dst.u6_addr.u6_addr64[1];

        key.hashval = flow.ip_tuple.v6.dst[0] + flow.ip_tuple.v6.dst[1] + flow.ip_tuple.v6.src[0] + flow.ip_tuple.v6.src[1] +
                        flow.l4_protocol + flow.src_port + flow.dst_port;

        //flow.hashval += flow.l4_protocol + flow.src_port + flow.dst_port;

        //pkt_infos.hashed_index = (uint64_t) flow.hashval % reader->getMaxActiveFlows();
        //pkt_infos.tree_result = ndpi_tfind(&flow, &reader->getActiveFlows()[pkt_infos.hashed_index], ndpi_workflow_node_cmp);
	flow.hashval = key.hashval;
        pkt_infos.tree_result = reader->getActiveFlows()->find(flow);
       // pkt_infos.tree_result = reader->getActiveFlows()->find(key);

        //pkt_infos.hashed_index = (uint64_t) flow.hashval % reader->getMaxActiveFlows();
        //pkt_infos.tree_result = ndpi_tfind(&flow, &reader->getActiveFlows()[pkt_infos.hashed_index], ndpi_workflow_node_cmp);

        this->captured_stats.ip_pkts++;
        this->captured_stats.ip_bytes += pkt_infos.ip_size;

	return 0;
    }
    case 2: { // Tunneled IPv4
        pkt_infos.ethernet = (struct ndpi_ethhdr *) &packet[pkt_infos.eth_offset];
        pkt_infos.ip_offset = sizeof(struct ndpi_ethhdr) + pkt_infos.eth_offset;
        pkt_infos.ip = (struct ndpi_iphdr *)(&packet[pkt_infos.ip_offset]);
        pkt_infos.ip6 = nullptr;
        pkt_infos.ip_size = pDyn1->capLength - pDyn1->descrLength - pkt_infos.ip_offset;

        flow.setFlowL3Type(4);

                pkt_infos.l4_ptr = &packet[pDyn1->offset1];

        /* Analyse lvl 4 */
        if (pDyn1->ipProtocol == 6) {
            /*  TCP   */ 
            const struct ndpi_tcphdr * tcp;
            flow.l4_protocol = IPPROTO_TCP;

            tcp = (struct ndpi_tcphdr *)pkt_infos.l4_ptr;

            flow.src_port = ntohs(tcp->source);
            flow.dst_port = ntohs(tcp->dest);
            key.src_port = ntohs(tcp->source);
            key.dst_port = ntohs(tcp->dest);

            this->captured_stats.tcp_pkts++;
        } else {
            /*  UDP   */
            const struct ndpi_udphdr * udp;
            flow.l4_protocol = IPPROTO_UDP;

            udp = (struct ndpi_udphdr *)pkt_infos.l4_ptr;

            flow.src_port = ntohs(udp->source);
            flow.dst_port = ntohs(udp->dest);
            key.src_port = ntohs(udp->source);
            key.dst_port = ntohs(udp->dest);

            this->captured_stats.udp_pkts++;
        }

        flow.ip_tuple.v4.src = pkt_infos.ip->saddr;
        flow.ip_tuple.v4.dst = pkt_infos.ip->daddr;

        key.l3_type = L3_IP;

        key.ip_tuple.v4.src = pkt_infos.ip->saddr;
        key.ip_tuple.v4.dst = pkt_infos.ip->daddr;

        key.hashval = flow.ip_tuple.v4.src + flow.ip_tuple.v4.dst + flow.l4_protocol + flow.src_port + flow.dst_port;

        //flow.hashval += flow.l4_protocol + flow.src_port + flow.dst_port;

        //pkt_infos.hashed_index = (uint64_t) flow.hashval % reader->getMaxActiveFlows();
        //pkt_infos.tree_result = ndpi_tfind(&flow, &reader->getActiveFlows()[pkt_infos.hashed_index], ndpi_workflow_node_cmp);
	flow.hashval = key.hashval;
        pkt_infos.tree_result = reader->getActiveFlows()->find(flow);
        //pkt_infos.tree_result = reader->getActiveFlows()->find(key);
        return 0;
    }
    case 3: { // Tunneled IPv6
        /*  Lvl 2   */
        pkt_infos.ethernet = (struct ndpi_ethhdr *) &packet[pkt_infos.eth_offset];
        pkt_infos.ip_offset = sizeof(struct ndpi_ethhdr) + pkt_infos.eth_offset;
        pkt_infos.ip = nullptr;
        pkt_infos.ip6 = (struct ndpi_ipv6hdr *)&packet[pkt_infos.ip_offset];

        pkt_infos.ip_size = pDyn1->capLength - pDyn1->descrLength - pkt_infos.ip_offset;

        flow.setFlowL3Type(6);   

        /* Analyse lvl 4 */
        if (pDyn1->ipProtocol == 6) {
            /*  TCP   */ 
            const struct ndpi_tcphdr * tcp;
            flow.l4_protocol = IPPROTO_TCP;

            tcp = (struct ndpi_tcphdr *)pkt_infos.l4_ptr;

            flow.src_port = ntohs(tcp->source);
            flow.dst_port = ntohs(tcp->dest);
            key.src_port = ntohs(tcp->source);
            key.dst_port = ntohs(tcp->dest);

            this->captured_stats.tcp_pkts++;
        } else {
            /*  UDP   */
            const struct ndpi_udphdr * udp;
            flow.l4_protocol = IPPROTO_UDP;

            udp = (struct ndpi_udphdr *)pkt_infos.l4_ptr;

            flow.src_port = ntohs(udp->source);
            flow.dst_port = ntohs(udp->dest);
            key.src_port = ntohs(udp->source);
            key.dst_port = ntohs(udp->dest);

            this->captured_stats.udp_pkts++;
        }
        
        flow.ip_tuple.v6.src[0] = pkt_infos.ip6->ip6_src.u6_addr.u6_addr64[0];
        flow.ip_tuple.v6.src[1] = pkt_infos.ip6->ip6_src.u6_addr.u6_addr64[1];
        flow.ip_tuple.v6.dst[0] = pkt_infos.ip6->ip6_dst.u6_addr.u6_addr64[0];
        flow.ip_tuple.v6.dst[1] = pkt_infos.ip6->ip6_dst.u6_addr.u6_addr64[1];

        key.l3_type = L3_IP6;

        key.ip_tuple.v6.src[0] = pkt_infos.ip6->ip6_src.u6_addr.u6_addr64[0];
        key.ip_tuple.v6.src[1] = pkt_infos.ip6->ip6_src.u6_addr.u6_addr64[1];
        key.ip_tuple.v6.dst[0] = pkt_infos.ip6->ip6_dst.u6_addr.u6_addr64[0];
        key.ip_tuple.v6.dst[1] = pkt_infos.ip6->ip6_dst.u6_addr.u6_addr64[1];

        key.hashval = flow.ip_tuple.v6.dst[0] + flow.ip_tuple.v6.dst[1] + flow.ip_tuple.v6.src[0] + flow.ip_tuple.v6.src[1] +
                        flow.l4_protocol + flow.src_port + flow.dst_port;

	flow.hashval = key.hashval;

        //flow.hashval += flow.l4_protocol + flow.src_port + flow.dst_port;

        //pkt_infos.hashed_index = (uint64_t) flow.hashval % reader->getMaxActiveFlows();
        //pkt_infos.tree_result = ndpi_tfind(&flow, &reader->getActiveFlows()[pkt_infos.hashed_index], ndpi_workflow_node_cmp);

        pkt_infos.tree_result = reader->getActiveFlows()->find(flow);

        //pkt_infos.hashed_index = (uint64_t) flow.hashval % reader->getMaxActiveFlows();
        //pkt_infos.tree_result = ndpi_tfind(&flow, &reader->getActiveFlows()[pkt_infos.hashed_index], ndpi_workflow_node_cmp);

        this->captured_stats.ip_pkts++;
        this->captured_stats.ip_bytes += pkt_infos.ip_size;
 	return 0;
    }
    }

    return -1;
}

/* ********************************** */
