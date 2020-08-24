#include "ndpi_light_includes.h"




/* ********************************** */

int NtDissector::DumpL4(FlowInfo& flow,
                        struct ndpi_support& pkt_infos)
{
    if (flow.l4_protocol == IPPROTO_TCP) {
        /*  TCP   */
        const struct ndpi_tcphdr * tcp;

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

        udp = (struct ndpi_udphdr *)pkt_infos.l4_ptr;
        flow.src_port = ntohs(udp->source);
        flow.dst_port = ntohs(udp->dest);

        this->captured_stats.udp_pkts++;
    }

    return 0;
}

/* ********************************** */
/*uint32_t parseIPV4string(uint8_t* ipAddress) {
  uint8_t* ipbytes[4];
  sscanf(ipAddress, "%d.%d.%d.%d", ipbytes[3], ipbytes[2], ipbytes[1], ipbytes[0]);
  return ipbytes[0] | ipbytes[1] << 8 | ipbytes[2] << 16 | ipbytes[3] << 24;
}*/
int NtDissector::DumpIPv4(FlowInfo& flow,
                            NtDyn1Descr_t* & pDyn1,
                            uint8_t* & packet,
                            struct ndpi_support& pkt_infos)
{
    /*  Lvl 2   */
    pkt_infos.ethernet = (struct ndpi_ethhdr *) &packet[pkt_infos.eth_offset];
    pkt_infos.ip_offset = sizeof(struct ndpi_ethhdr) + pkt_infos.eth_offset;
    pkt_infos.ip = (struct ndpi_iphdr *)(&packet[pkt_infos.ip_offset]);
    pkt_infos.ip6 = nullptr;
    //printf("timestamp: %d\n", pDyn1->timestamp);
    /*  Lvl 3   */

    pkt_infos.ip_size = pDyn1->capLength - pDyn1->descrLength - pkt_infos.ip_offset;
  
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

    flow.ip_tuple.v4.src = pkt_infos.ip->saddr;
    flow.ip_tuple.v4.dst = pkt_infos.ip->daddr;
 /*   uint32_t prova = parseIPV4string(packet + pDyn1->offset0);
	printf("%d, %d\n", pkt_infos.ip->saddr, prova);
   */ this->captured_stats.ip_pkts++;
    this->captured_stats.ip_bytes += pkt_infos.ip_size;

    if(DumpL4(flow, pkt_infos) != 0)
        return -1;
    
    return 0;
}

/* ********************************** */

int NtDissector::DumpIPv6(FlowInfo& flow,
                            NtDyn1Descr_t* & pDyn1,
                            uint8_t* & packet,
                            struct ndpi_support& pkt_infos)
{
    /*  Lvl 2   */
    pkt_infos.ethernet = (struct ndpi_ethhdr *) &packet[pkt_infos.eth_offset];
    pkt_infos.ip_offset = sizeof(struct ndpi_ethhdr) + pkt_infos.eth_offset;
    pkt_infos.ip = nullptr;
    pkt_infos.ip6 = (struct ndpi_ipv6hdr *)&packet[pkt_infos.ip_offset];

    /*  Lvl 3   */

    pkt_infos.ip_size = pDyn1->capLength - pDyn1->descrLength - pkt_infos.ip_offset;

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

    this->captured_stats.ip_pkts++;
    this->captured_stats.ip_bytes += pkt_infos.ip_size;

    if(DumpL4(flow, pkt_infos) != 0)
        return -1;

    return 0;
}

/* ********************************** */


int NtDissector::getDyn(NtNetBuf_t& hNetBuffer,
                        FlowInfo& flow,
                        NtDyn1Descr_t* & pDyn1,
                        struct ndpi_support& pkt_infos)
{
    // descriptor DYN1 is used, which is set up via NTPL.
    pDyn1 = NT_NET_DESCR_PTR_DYN1(hNetBuffer);
    uint8_t* packet = reinterpret_cast<uint8_t*>(pDyn1) + pDyn1->descrLength;

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
                    if(DumpIPv4(flow, pDyn1, packet, pkt_infos) != 0)
                        return -1;
                    break;
            case 1:  // IPv6
                    if(DumpIPv6(flow, pDyn1, packet, pkt_infos) != 0)
                        return -1;
                    break;
            case 2:  // Tunneled IPv4
                    if(DumpIPv4(flow, pDyn1, packet, pkt_infos) != 0)
                        return -1;
                    break;
            case 3:  // Tunneled IPv6
                    if(DumpIPv6(flow, pDyn1, packet, pkt_infos) != 0)
                        return -1;
                    break;
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
                                struct ndpi_support & pkt_infos)
{
    NapatechReader * reader = (NapatechReader *) args;

    NtNetBuf_t * hNetBuffer = ((NtNetBuf_t *) header_tmp);

    NtDyn1Descr_t* pDyn1;

    this->captured_stats.packets_captured++;

    // Updating time counters
    if(!this->captured_stats.nt_time_start)
    	this->captured_stats.nt_time_start = (uint64_t) NT_NET_GET_PKT_TIMESTAMP(* hNetBuffer);
        
    this->captured_stats.nt_time_end = (uint64_t) NT_NET_GET_PKT_TIMESTAMP(* hNetBuffer);
    //printf("timestamp type: %d, %d\n", NT_NET_GET_PKT_TIMESTAMP_TYPE(* hNetBuffer), NT_NET_GET_PKT_TIMESTAMP(* hNetBuffer));
    pkt_infos.time_ms = NT_NET_GET_PKT_TIMESTAMP(* hNetBuffer);
    // Checking idle flows
    reader->newPacket((void *)hNetBuffer);
/*
    if(this->searchVal(reader, flow, pkt_infos.tree_result, pkt_infos.hashed_index) == 0) {
        reader->setNewFlow(false);

        pkt_infos.flow_to_process = *(FlowInfo **)pkt_infos.tree_result;

        if(pkt_infos.flow_to_process->ended_dpi != 0)
            return 2;       
    }
*/
    // Parsing packets
    if(this->getDyn(* hNetBuffer, flow, pDyn1, pkt_infos) != 0)
        return -1;
    
    this->captured_stats.packets_processed++;
    this->captured_stats.total_l4_data_len += pkt_infos.l4_len;

    //reader->setNewFlow(true);

    return 0;
}

/* ********************************** */
