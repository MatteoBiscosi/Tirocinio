#include "ndpi_light_includes.h"


static uint32_t flow_id = 0;


/* ********************************** */

int PcapDissector::processL2(PcapReader * const reader,
                                pcap_pkthdr const * const header,
                                uint8_t const * const packet,
                                struct ndpi_support & pkt_infos)
{
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
            switch (type) {
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
                                        this->captured_stats.packets_captured, type);
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
                            struct ndpi_support & pkt_infos)
{
    if (pkt_infos.type == ETH_P_IP) {
        pkt_infos.ip = (struct ndpi_iphdr *)&packet[pkt_infos.ip_offset];
        pkt_infos.ip6 = nullptr;
    } else if (type == ETH_P_IPV6) {
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
                          struct ndpi_support & pkt_infos)
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
                          struct ndpi_support & pkt_infos)
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

    return 0;
}

/* ********************************** */

void PcapDissector::parsePacket(FlowInfo flow
                                Reader * & const args,
                                void * header_tmp,
                                void * packet_tmp,
                                struct ndpi_support & pkt_infos)
{
    PcapReader * reader = (PcapReader *) args;
       
    pcap_pkthdr const * const header = (pcap_pkthdr const * const) header_tmp;
    uint8_t const * const packet = (uint8_t const * const) packet_tmp;

    this->captured_stats.packets_captured++;
    if(!this->captured_stats.pcap_start.tv_sec) {
        this->captured_stats.pcap_start.tv_sec = header->ts.tv_sec ;
        this->captured_stats.pcap_start.tv_usec = header->ts.tv_usec;
    }
    this->captured_stats.pcap_end.tv_sec = header->ts.tv_sec;
    this->captured_stats.pcap_end.tv_usec = header->ts.tv_usec;

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

    return 0;
/*
    this->captured_stats.packets_processed++;
    this->captured_stats.total_l4_data_len += pkt_infos.l4_len;

    if(this->searchVal(reader, flow, pkt_infos) != 0) {
        if(this->addVal(reader, flow, pkt_infos) != 0) {
            this->captured_stats.discarded_bytes += header->len;
            return;
        }
        else
            this->captured_stats.total_flows_captured++;
    } else {
        pkt_infos.flow_to_process = *(FlowInfo **)pkt_infos.tree_result;

        if (pkt_infos.ndpi_src != pkt_infos.flow_to_process->ndpi_src) {
            pkt_infos.ndpi_src = pkt_infos.flow_to_process->ndpi_dst;
            pkt_infos.ndpi_dst = pkt_infos.flow_to_process->ndpi_src;
        } else {
            pkt_infos.ndpi_src = pkt_infos.flow_to_process->ndpi_src;
            pkt_infos.ndpi_dst = pkt_infos.flow_to_process->ndpi_dst;
        }
    }

    pkt_infos.flow_to_process->packets_processed++;
    pkt_infos.flow_to_process->total_l4_data_len += pkt_infos.l4_len;
    /* update timestamps, important for timeout handling */
 /*   if (pkt_infos.flow_to_process->first_seen == 0) {
 /*       pkt_infos.flow_to_process->first_seen = pkt_infos.time_ms;
    }
 /*   pkt_infos.flow_to_process->last_seen = pkt_infos.time_ms;
    /* current packet is an TCP-ACK? */
/*    pkt_infos.flow_to_process->flow_ack_seen = flow.flow_ack_seen;

    /* TCP-FIN: indicates that at least one side wants to end the connection */
 /*   if (flow.flow_fin_ack_seen != 0 && pkt_infos.flow_to_process->flow_fin_ack_seen == 0) {
        pkt_infos.flow_to_process->flow_fin_ack_seen = 1;
        tracer->traceEvent(4, "[%8llu, %4u] end of flow\n",
                                    this->captured_stats.packets_captured, flow_to_process->flow_id);
        this->captured_stats.discarded_bytes += header->len;
        return;
    }

    this->printFlowInfos(reader, pkt_infos);*/
}

/* ********************************** */
