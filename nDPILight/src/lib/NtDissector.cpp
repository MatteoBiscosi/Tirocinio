#include "ndpi_light_includes.h"



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
    //tracer->traceEvent(2, "final packets: %llu\n", (long long unsigned int)hStat.u.query_v3.data.port.aPorts[0].rx.RMON1.pkts);
    this->captured_stats.packets_captured = (long long unsigned int)hStat.u.query_v3.data.port.aPorts[0].rx.extDrop.pktsFilterDrop + this->captured_stats.packets_captured;
    this->captured_stats.total_wire_bytes = (long long unsigned int)hStat.u.query_v3.data.port.aPorts[0].rx.extDrop.octetsFilterDrop + this->captured_stats.total_wire_bytes;
    delta = this->captured_stats.packets_captured - this->captured_stats.previous_packets;
    this->captured_stats.previous_packets = this->captured_stats.packets_captured;

    tracer->traceEvent(2, "\tCapture brief summary: Tot. packets: %llu | Tot. bytes: %llu | pps: %llu\r\n",
                                this->captured_stats.packets_captured, this->captured_stats.total_wire_bytes, delta);
}

/* ********************************** */

int NtDissector::DumpIPv4(Reader * & reader,
                            FlowInfo& flow,
                            NtDyn1Descr_t* & pDyn1,
                            uint8_t* & packet,
                            PacketInfo& pkt_infos)
{
    
    struct ports * pktPorts = (struct ports *) &packet[pDyn1->offset1]; 
    
    /*  Lvl 2   */
    pkt_infos.ethernet = (struct ndpi_ethhdr *) &packet[pkt_infos.eth_offset];
    pkt_infos.ip_offset = sizeof(struct ndpi_ethhdr) + pkt_infos.eth_offset;
    pkt_infos.ip = (struct ndpi_iphdr *)(&packet[pkt_infos.ip_offset]);
    pkt_infos.ip6 = nullptr; 
    pkt_infos.ip_size = pDyn1->capLength - pDyn1->descrLength - pkt_infos.ip_offset;
    //printf("%llu, %llu\n", pkt_infos.ip_size, pkt_infos.ip_offset);
    flow.setFlowL3Type(4);
    //printf("%d\n", pkt_infos.ip_size);
    /* Search if the record is already inside the structure */
    flow.ip_tuple.v4.src = pkt_infos.ip->saddr;
    flow.ip_tuple.v4.dst = pkt_infos.ip->daddr;

    flow.src_port = ntohs(pktPorts->srcPort);
    flow.dst_port = ntohs(pktPorts->dstPort);

    this->captured_stats.ip_pkts++;
    this->captured_stats.ip_bytes += pkt_infos.ip_size;

    if(this->searchVal(reader, flow, pkt_infos) == 0)
        return 2;    

    /*  Lvl 3   */
    if (pkt_infos.ip_size < sizeof(*pkt_infos.ip)) {
        tracer->traceEvent(0, "[%8llu] Packet smaller than IP4 header length: %u < %zu, pkt_lenght: %d\n", 
                                this->captured_stats.packets_captured, pkt_infos.ip_size, sizeof(*pkt_infos.ip),
                                pDyn1->capLength - pDyn1->descrLength); 
        this->captured_stats.discarded_bytes += pkt_infos.ip_size;
	return -1;
    }
   
    if (ndpi_detection_get_l4((uint8_t*)pkt_infos.ip, pkt_infos.ip_size, &pkt_infos.l4_ptr, &pkt_infos.l4_len,
                                &flow.l4_protocol, NDPI_DETECTION_ONLY_IPV4) != 0)
    {

        tracer->traceEvent(0, "[%8llu] nDPI IPv4/L4 payload detection failed, L4 length: %zu\n",
                                this->captured_stats.packets_captured, pkt_infos.ip_size - sizeof(*pkt_infos.ip));
     	this->captured_stats.discarded_bytes += pkt_infos.ip_size;
	return -1;
    }
    

    /* Analyse lvl 4 */
    if (flow.l4_protocol == IPPROTO_TCP) {
        /*  TCP   */
        const struct ndpi_tcphdr * tcp;

        tcp = (struct ndpi_tcphdr *)pkt_infos.l4_ptr;

        /*  Checks the state of the flow */
        flow.is_midstream_flow = (tcp->syn == 0 ? 1 : 0);
        flow.flow_fin_ack_seen = (tcp->fin == 1 && tcp->ack == 1 ? 1 : 0);
        flow.flow_ack_seen = tcp->ack;

    } else if (flow.l4_protocol == IPPROTO_UDP) {
        /*  UDP   */
        const struct ndpi_udphdr * udp;

        udp = (struct ndpi_udphdr *)pkt_infos.l4_ptr;

    } else {
	this->captured_stats.discarded_bytes += pkt_infos.ip_size;
        return -1;
    }
    
    return 1;
}

/* ********************************** */

int NtDissector::DumpIPv6(Reader * & reader,
                            FlowInfo& flow,
                            NtDyn1Descr_t* & pDyn1,
                            uint8_t* & packet,
                            PacketInfo& pkt_infos)
{
    struct ports * pktPorts = (struct ports *) &packet[pDyn1->offset1];

    /*  Lvl 2   */
    pkt_infos.ethernet = (struct ndpi_ethhdr *) &packet[pkt_infos.eth_offset];
    pkt_infos.ip_offset = sizeof(struct ndpi_ethhdr) + pkt_infos.eth_offset;
    pkt_infos.ip = nullptr;
    pkt_infos.ip6 = (struct ndpi_ipv6hdr *)&packet[pkt_infos.ip_offset];

    pkt_infos.ip_size = pDyn1->capLength - pDyn1->descrLength - pkt_infos.ip_offset;

    
    flow.ip_tuple.v6.src[0] = pkt_infos.ip6->ip6_src.u6_addr.u6_addr64[0];
    flow.ip_tuple.v6.src[1] = pkt_infos.ip6->ip6_src.u6_addr.u6_addr64[1];
    flow.ip_tuple.v6.dst[0] = pkt_infos.ip6->ip6_dst.u6_addr.u6_addr64[0];
    flow.ip_tuple.v6.dst[1] = pkt_infos.ip6->ip6_dst.u6_addr.u6_addr64[1];
 
    flow.setFlowL3Type(6);   

    flow.src_port = ntohs(pktPorts->srcPort);
    flow.dst_port = ntohs(pktPorts->dstPort);

    this->captured_stats.ip_pkts++;
    this->captured_stats.ip_bytes += pkt_infos.ip_size;

    if(this->searchVal(reader, flow, pkt_infos) == 0)
        return 2;

    /*  Lvl 3   */
    if (pkt_infos.ip_size < sizeof(pkt_infos.ip6->ip6_hdr)) {
        tracer->traceEvent(0, "[%8llu] Packet smaller than IP6 header length: %u < %zu\n",
                                this->captured_stats.packets_captured, pkt_infos.ip_size, sizeof(pkt_infos.ip6->ip6_hdr));
	this->captured_stats.discarded_bytes += pkt_infos.ip_size;
        return -1;
    }

    if (ndpi_detection_get_l4((uint8_t*)pkt_infos.ip6, pkt_infos.ip_size, &pkt_infos.l4_ptr, &pkt_infos.l4_len,
                                &flow.l4_protocol, NDPI_DETECTION_ONLY_IPV6) != 0)
    {   
        tracer->traceEvent(0, "[%8llu] nDPI IPv6/L4 payload detection failed, L4 length: %zu\n",
                                this->captured_stats.packets_captured, pkt_infos.ip_size - sizeof(*pkt_infos.ip));
	this->captured_stats.discarded_bytes += pkt_infos.ip_size;
        return -1;
    }

    /* Analyse lvl 4 */
    if (flow.l4_protocol == IPPROTO_TCP) {
        /*  TCP   */
        const struct ndpi_tcphdr * tcp;

        tcp = (struct ndpi_tcphdr *)pkt_infos.l4_ptr;

        /*  Checks the state of the flow */
        flow.is_midstream_flow = (tcp->syn == 0 ? 1 : 0);
        flow.flow_fin_ack_seen = (tcp->fin == 1 && tcp->ack == 1 ? 1 : 0);
        flow.flow_ack_seen = tcp->ack;

    } else if (flow.l4_protocol == IPPROTO_UDP) {
        /*  UDP   */
        const struct ndpi_udphdr * udp;

        udp = (struct ndpi_udphdr *)pkt_infos.l4_ptr;

    } else {
	this->captured_stats.discarded_bytes += pkt_infos.ip_size;
        return -1;
    }
    return 1;
}

/* ********************************** */

int NtDissector::parsePacket(FlowInfo & flow,
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
                    return DumpIPv4(args, flow, pDyn1, packet, pkt_infos);
            case 1:  // IPv6
                    return DumpIPv6(args, flow, pDyn1, packet, pkt_infos);
            case 2:  // Tunneled IPv4
                    return DumpIPv4(args, flow, pDyn1, packet, pkt_infos);
            case 3:  // Tunneled IPv6
                    return DumpIPv6(args, flow, pDyn1, packet, pkt_infos);
            }
        }
    }
}

/* ********************************** */
