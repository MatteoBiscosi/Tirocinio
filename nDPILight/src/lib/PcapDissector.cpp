#include "ndpi_light_includes.h"


static uint32_t flow_id = 0;


/* ********************************** */

void PcapDissector::printBriefInfos(Reader *reader)
{
    uint64_t act_packets = this->captured_stats.packets_captured;
    uint64_t delta = act_packets - this->captured_stats.previous_packets;
    this->captured_stats.previous_packets = act_packets;
    tracer->traceEvent(2, "\tCapture brief summary: Tot. packets: %llu | Tot. bytes: %llu | pps: %llu\r\n",
                        this->captured_stats.packets_captured, this->captured_stats.total_wire_bytes,
                        delta);
}

/* ********************************** */

int PcapDissector::processL2(PcapReader * const reader,
                                pcap_pkthdr const * const header,
                                uint8_t const * const packet,
                                PacketInfo & pkt_infos)
{
    pkt_infos.eth_offset = 0;
    switch (pcap_datalink(reader->getPcapHandle())) {
        case DLT_NULL:
            /*  Loopback    */
            if (ntohl(*((uint32_t *)&packet[pkt_infos.eth_offset])) == 0x00000002) {
                pkt_infos.type = ETH_P_IP;
            } else {
                pkt_infos.type = ETH_P_IPV6;
            }
            pkt_infos.ip_offset = 4 + pkt_infos.eth_offset;
            break;
        case DLT_EN10MB:
            /*  Ethernet    */
            if (header->len < sizeof(struct ndpi_ethhdr)) {
                tracer->traceEvent(1, "[%8llu] Ethernet packet too short - skipping\n", this->captured_stats.packets_captured);
                return -1;
            }

            pkt_infos.ethernet = (struct ndpi_ethhdr *) &packet[pkt_infos.eth_offset];
	 
            pkt_infos.ip_offset = sizeof(struct ndpi_ethhdr) + pkt_infos.eth_offset;
            pkt_infos.type = ntohs(pkt_infos.ethernet->h_proto);

            switch (pkt_infos.type) {
                case ETH_P_IP:
                    /* IPv4 */
                    if (header->len < sizeof(struct ndpi_ethhdr) + sizeof(struct ndpi_iphdr)) {
                        tracer->traceEvent(1, "[%8llu] Ethernet packet too short - skipping\n", this->captured_stats.packets_captured);
                        return -1;
                    }
                    break;

                case ETH_P_IPV6:
                    /* IPV6 */
                    if (header->len < sizeof(struct ndpi_ethhdr) + sizeof(struct ndpi_ipv6hdr)) {
                        tracer->traceEvent(1, "[%8llu] Ethernet packet too short - skipping\n", this->captured_stats.packets_captured);
                        return -1;
                    }
                    break;

                case ETH_P_ARP:
                    /* ARP */
                    return -1;

                default:
                    tracer->traceEvent(1, "[%8llu] Unknown Ethernet packet with type 0x%X - skipping\n", 
                                        this->captured_stats.packets_captured, pkt_infos.type);
                    return -1;
            }
            break;
        default:
            tracer->traceEvent(1, "[%8llu] Captured non IP/Ethernet packet with datalink type 0x%X - skipping\n",
                                    this->captured_stats.packets_captured, 
                                    pcap_datalink(reader->getPcapHandle()));
            return -1;
    }

    return 0;
}

/* ********************************** */

int PcapDissector::setL2Ip(pcap_pkthdr const * const header,
                            uint8_t const * const packet,
                            PacketInfo & pkt_infos)
{
    if (pkt_infos.type == ETH_P_IP) {
        pkt_infos.ip = (struct ndpi_iphdr *)&packet[pkt_infos.ip_offset];
        pkt_infos.ip6 = nullptr;
    } else if (pkt_infos.type == ETH_P_IPV6) {
        pkt_infos.ip = nullptr;
        pkt_infos.ip6 = (struct ndpi_ipv6hdr *)&packet[pkt_infos.ip_offset];
    } else {
        tracer->traceEvent(1, "[%8llu] Captured non IPv4/IPv6 packet with type 0x%X - skipping\n",
                            this->captured_stats.packets_captured, pkt_infos.type); 
        return -1;
    }

    pkt_infos.ip_size = header->len - pkt_infos.ip_offset;

    if (pkt_infos.type == ETH_P_IP && header->len >= pkt_infos.ip_offset) {
        if (header->caplen < header->len) {
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
                          PacketInfo & pkt_infos)
{
    if (pkt_infos.ip != nullptr && pkt_infos.ip->version == 4) {
        /*  IPv4    */
        if (pkt_infos.ip_size < sizeof(*pkt_infos.ip)) {
            tracer->traceEvent(0, "[%8llu] Packet smaller than IP4 header length: %u < %zu\n", 
                                    this->captured_stats.packets_captured, pkt_infos.ip_size, sizeof(*pkt_infos.ip)); 
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

        flow.ip_tuple.v4.src = pkt_infos.ip->saddr;
        flow.ip_tuple.v4.dst = pkt_infos.ip->daddr;

        flow.hashval = flow.ip_tuple.v4.src + flow.ip_tuple.v4.dst;

    } else if (pkt_infos.ip6 != nullptr) {
        /*  IPv6    */
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

        flow.ip_tuple.v6.src[0] = pkt_infos.ip6->ip6_src.u6_addr.u6_addr64[0];
        flow.ip_tuple.v6.src[1] = pkt_infos.ip6->ip6_src.u6_addr.u6_addr64[1];
        flow.ip_tuple.v6.dst[0] = pkt_infos.ip6->ip6_dst.u6_addr.u6_addr64[0];
        flow.ip_tuple.v6.dst[1] = pkt_infos.ip6->ip6_dst.u6_addr.u6_addr64[1];

        flow.hashval = flow.ip_tuple.v6.src[0] + flow.ip_tuple.v6.src[1];
		flow.hashval += flow.ip_tuple.v6.dst[0] + flow.ip_tuple.v6.dst[1];
    } else {
        tracer->traceEvent(0, "[%8llu] Non IP/IPv6 protocol detected: 0x%X\n",
                                this->captured_stats.packets_captured, pkt_infos.type);
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
                          PacketInfo & pkt_infos)
{
    if (flow.l4_protocol == IPPROTO_TCP) {
        /*  TCP   */
        const struct ndpi_tcphdr * tcp;

        if (header->len < (pkt_infos.l4_ptr - packet) + sizeof(struct ndpi_tcphdr)) {
            tracer->traceEvent(0, "[%8llu] Malformed TCP packet, packet size smaller than expected: %u < %zu\n",
                                this->captured_stats.packets_captured, header->len, (pkt_infos.l4_ptr - packet) + sizeof(struct ndpi_tcphdr));
            return -1;
        }

        tcp = (struct ndpi_tcphdr *)pkt_infos.l4_ptr;

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

        if (header->len < (pkt_infos.l4_ptr - packet) + sizeof(struct ndpi_udphdr)) {
            tracer->traceEvent(0, "[%8llu] Malformed UDP packet, packet size smaller than expected: %u < %zu\n",
                                this->captured_stats.packets_captured, header->len, (pkt_infos.l4_ptr - packet) + sizeof(struct ndpi_udphdr));
            return -1;
        }
        udp = (struct ndpi_udphdr *)pkt_infos.l4_ptr;
        flow.src_port = ntohs(udp->source);
        flow.dst_port = ntohs(udp->dest);

        this->captured_stats.udp_pkts++;
    }

    pkt_infos.l4_len = (pkt_infos.l4_ptr - packet);

    return 0;
}

/* ********************************** */

int PcapDissector::parsePacket(FlowInfo & flow,
                                Reader * & args,
                                void * header_tmp,
                                void * packet_tmp,
                                PacketInfo & pkt_infos)
{
    PcapReader * reader = (PcapReader *) args;
       
    pcap_pkthdr const * const header = (pcap_pkthdr const * const) header_tmp;
    uint8_t const * const packet = (uint8_t const * const) packet_tmp;

    struct timeval actual_time;
    gettimeofday(&actual_time, nullptr);
    
    pkt_infos.time_ms = ((uint64_t) actual_time.tv_sec) * TICK_RESOLUTION + actual_time.tv_usec / (1000000 / TICK_RESOLUTION);

    reader->newPacket((void *) header);

    /*  Process L2  */
    if(this->processL2(reader, header, packet, pkt_infos) != 0) {
        this->captured_stats.discarded_bytes += header->len;
        return -1;
    }

    if(this->setL2Ip(header, packet, pkt_infos) != 0) {
        this->captured_stats.discarded_bytes += header->len;
        return -1;
    }

    /*  Process L3  */
    if(this->processL3(flow, header, packet, pkt_infos) != 0) {
        this->captured_stats.discarded_bytes += header->len;
        return -1;
    }

    /*  Process L4  */
    if(this->processL4(flow, header, packet, pkt_infos) != 0) {
        this->captured_stats.discarded_bytes += header->len;
        return -1;
    }

    flow.hashval += flow.l4_protocol + flow.src_port + flow.dst_port;
    
    pkt_infos.tree_result = reader->getActiveFlows()->find(flow);

    return 0;
}

/* ********************************** */
