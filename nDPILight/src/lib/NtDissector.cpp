#include "ndpi_light_includes.h"



/* ********************************** */

void NtDissector::printBriefInfos(Reader *reader)
{
 /*   NtStatStream_t hStatStream;
    NtStatistics_t hStat;
    uint32_t hbCount;
    uint64_t tot_pkts = 0, tot_bytes = 0;
    NapatechReader *reader_tmp = (NapatechReader *) reader;
    //printf("%llu, %llu\n", reader_tmp->getInitPkts(), reader_tmp->getInitBytes()); 
    NT_StatOpen(&hStatStream, "ExampleStatUsage");
//    hStat.cmd = NT_STATISTICS_READ_CMD_QUERY_V3;
    hStat.cmd=NT_STATISTICS_READ_CMD_USAGE_DATA_V0;
//    hStat.u.usageData_v0.streamid = (uint8_t) STREAM_ID_MISS; 
    //printf("%llu, %llu\n", reader_tmp->getInitPkts(), reader_tmp->getInitBytes());
//	hStat.u.query_v3.poll = 0;
//  hStat.u.query_v3.clear = 1;
    NT_StatRead(hStatStream, &hStat);

    for (hbCount = 0; hbCount < hStat.u.usageData_v0.data.numHostBufferUsed; hbCount++) {
        tot_pkts += hStat.u.usageData_v0.data.hb[hbCount].stat.drop.frames;
        tot_bytes += hStat.u.usageData_v0.data.hb[hbCount].stat.drop.bytes;
    }
    tot_pkts = tot_pkts - reader_tmp->getInitPkts();
    tot_bytes = tot_bytes - reader_tmp->getInitBytes();
/*    uint64_t totDropsPkts = hStat.u.query_v3.data.stream.streamid[STREAM_ID_MISS].drop.pkts;
    uint64_t totDropsBytes = hStat.u.query_v3.data.stream.streamid[STREAM_ID_MISS].drop.octets;
printf("%llu, %llu\n", totDropsPkts, totDropsBytes);
    uint64_t act_packets = tot_pkts;
    uint64_t delta = act_packets - this->captured_stats.previous_packets;
    this->captured_stats.previous_packets = act_packets;
    tracer->traceEvent(2, "\tCapture brief summary: Tot. packets: %llu | Tot. bytes: %llu | Pkts. captured: %llu | Bytes captured: %llu | pps: %llu\r\n", 
			tot_pkts, tot_bytes, this->captured_stats.packets_processed, this->captured_stats.total_wire_bytes,
			delta);
*/
}


/* ********************************** */

int NtDissector::setupFlowToSearch(Reader * & reader,
				    uint8_t * packet,
                                    FlowInfo& flow,
                                    NtDyn1Descr_t* & pDyn1,
                                    PacketInfo& pkt_infos,
                                    int l3Type)
{
    if (l3Type == 4) {
        /*  IPv4    */
        flow.ip_tuple.v4.src = pkt_infos.ip->saddr;
        flow.ip_tuple.v4.dst = pkt_infos.ip->daddr;

    } else if (l3Type == 6) {
        /*  IPv6    */
        flow.ip_tuple.v6.src[0] = pkt_infos.ip6->ip6_src.u6_addr.u6_addr64[0];
        flow.ip_tuple.v6.src[1] = pkt_infos.ip6->ip6_src.u6_addr.u6_addr64[1];
        flow.ip_tuple.v6.dst[0] = pkt_infos.ip6->ip6_dst.u6_addr.u6_addr64[0];
        flow.ip_tuple.v6.dst[1] = pkt_infos.ip6->ip6_dst.u6_addr.u6_addr64[1];
    }

    struct ports * pktPorts = (struct ports *) &packet[pDyn1->offset1];

    flow.src_port = ntohs(pktPorts->srcPort);
    flow.dst_port = ntohs(pktPorts->dstPort);

    if(this->searchVal(reader, flow, pkt_infos) != 0)
        return -1;

    this->captured_stats.ip_pkts++;
    this->captured_stats.ip_bytes += pkt_infos.ip_size;

    return 0;
}

/* ********************************** */

int NtDissector::DumpIPv4(Reader * & reader,
                            FlowInfo& flow,
                            NtDyn1Descr_t* & pDyn1,
                            uint8_t* & packet,
                            PacketInfo& pkt_infos)
{
    /*  Lvl 2   */
    pkt_infos.ethernet = (struct ndpi_ethhdr *) &packet[pkt_infos.eth_offset];
    pkt_infos.ip_offset = sizeof(struct ndpi_ethhdr) + pkt_infos.eth_offset;
    pkt_infos.ip = (struct ndpi_iphdr *)(&packet[pkt_infos.ip_offset]);
    pkt_infos.ip6 = nullptr;
    
    pkt_infos.ip_size = pDyn1->capLength - pDyn1->descrLength - pkt_infos.ip_offset;
    
    if(setupFlowToSearch(reader, packet, flow, pDyn1, pkt_infos, 4) == 0)
        return 2;

    /*  Lvl 3   */
    if (pkt_infos.ip_size < sizeof(*pkt_infos.ip)) {
        tracer->traceEvent(0, "[%8llu] Packet smaller than IP4 header length: %u < %zu, pkt_lenght: %d\n", 
                                this->captured_stats.packets_captured, pkt_infos.ip_size, sizeof(*pkt_infos.ip),
                                pDyn1->capLength - pDyn1->descrLength); 
        return -1;
    }

    flow.setFlowL3Type(4);

    if (ndpi_detection_get_l4((uint8_t*)pkt_infos.ip, pkt_infos.ip_size, &pkt_infos.l4_ptr, &pkt_infos.l4_len,
                                &flow.l4_protocol, NDPI_DETECTION_ONLY_IPV4) != 0)
    {

        tracer->traceEvent(0, "[%8llu] nDPI IPv4/L4 payload detection failed, L4 length: %zu\n",
                                this->captured_stats.packets_captured, pkt_infos.ip_size - sizeof(*pkt_infos.ip));
        return -1;
    }

    this->captured_stats.ip_pkts++;
    this->captured_stats.ip_bytes += pkt_infos.ip_size;

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

    } else 
        return -1;
    
    return 1;
}

/* ********************************** */

int NtDissector::DumpIPv6(Reader * & reader,
                            FlowInfo& flow,
                            NtDyn1Descr_t* & pDyn1,
                            uint8_t* & packet,
                            PacketInfo& pkt_infos)
{
    /*  Lvl 2   */
    pkt_infos.ethernet = (struct ndpi_ethhdr *) &packet[pkt_infos.eth_offset];
    pkt_infos.ip_offset = sizeof(struct ndpi_ethhdr) + pkt_infos.eth_offset;
    pkt_infos.ip = nullptr;
    pkt_infos.ip6 = (struct ndpi_ipv6hdr *)&packet[pkt_infos.ip_offset];

    pkt_infos.ip_size = pDyn1->capLength - pDyn1->descrLength - pkt_infos.ip_offset;
   
    if(setupFlowToSearch(reader, packet, flow, pDyn1, pkt_infos, 4) == 0)
        return 2;

    /*  Lvl 3   */
    if (pkt_infos.ip_size < sizeof(pkt_infos.ip6->ip6_hdr)) {
        tracer->traceEvent(0, "[%8llu] Packet smaller than IP6 header length: %u < %zu\n",
                                this->captured_stats.packets_captured, pkt_infos.ip_size, sizeof(pkt_infos.ip6->ip6_hdr));
        return -1;
    }

    flow.setFlowL3Type(6);

    if (ndpi_detection_get_l4((uint8_t*)pkt_infos.ip6, pkt_infos.ip_size, &pkt_infos.l4_ptr, &pkt_infos.l4_len,
                                &flow.l4_protocol, NDPI_DETECTION_ONLY_IPV6) != 0)
    {   
        tracer->traceEvent(0, "[%8llu] nDPI IPv6/L4 payload detection failed, L4 length: %zu\n",
                                this->captured_stats.packets_captured, pkt_infos.ip_size - sizeof(*pkt_infos.ip));
        return -1;
    }

    this->captured_stats.ip_pkts++;
    this->captured_stats.ip_bytes += pkt_infos.ip_size;

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

    } else 
        return -1;

    return 1;
}

/* ********************************** */


int NtDissector::getDyn(Reader * & reader,
                        NtNetBuf_t& hNetBuffer,
                        FlowInfo& flow,
                        NtDyn1Descr_t* & pDyn1,
                        PacketInfo& pkt_infos)
{
    // descriptor DYN1 is used, which is set up via NTPL.
    pDyn1 = NT_NET_DESCR_PTR_DYN1(hNetBuffer);
    uint8_t* packet = (uint8_t *) NT_NET_GET_PKT_L2_PTR(hNetBuffer);

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
                    return DumpIPv4(reader, flow, pDyn1, packet, pkt_infos);
            case 1:  // IPv6
                    return DumpIPv6(reader, flow, pDyn1, packet, pkt_infos);
            case 2:  // Tunneled IPv4
                    return DumpIPv4(reader, flow, pDyn1, packet, pkt_infos);
            case 3:  // Tunneled IPv6
                    return DumpIPv6(reader, flow, pDyn1, packet, pkt_infos);
            }
        }
    }

    return 0;
}

/* ********************************** */

int NtDissector::parsePacket(FlowInfo & flow,
                                Reader * & args,
                                void * header_tmp,
                                void * packet_tmp,
                                PacketInfo & pkt_infos)
{
/*    NapatechReader * reader = (NapatechReader *) args;
    NtNetBuf_t * hNetBuffer = ((NtNetBuf_t *) header_tmp);
    NtDyn1Descr_t* pDyn1;

    // Updating time counters
    pkt_infos.time_ms = NT_NET_GET_PKT_TIMESTAMP(* hNetBuffer);
    pkt_infos.eth_offset = 0;
    // Checking idle flows
//    reader->newPacket((void *)hNetBuffer);
*/
    // Parsing packets
    //return this->getDyn(args, * hNetBuffer, flow, pDyn1, pkt_infos);
}

/* ********************************** */
