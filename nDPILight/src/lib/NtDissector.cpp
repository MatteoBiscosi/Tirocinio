#include "ndpi_light_includes.h"




/* ********************************** */

int NtDissector::DumpL4(FlowInfo& flow,
                        struct ndpi_support& pkt_infos)
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
                            struct ndpi_support& pkt_infos)
{
    /*  Lvl 2   */
    pkt_infos.ethernet = (struct ndpi_ethhdr *) &packet[pkt_infos.eth_offset];
    pkt_infos.ip_offset = sizeof(struct ndpi_ethhdr) + pkt_infos.eth_offset;
    pkt_infos.ip = (struct ndpi_iphdr *)(&packet[pkt_infos.ip_offset]);
    pkt_infos.ip6 = nullptr;

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

    flow.ip_tuple.v4.src = ip->saddr;
    flow.ip_tuple.v4.dst = ip->daddr;

    this->captured_stats.ip_pkts++;
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
    pkt_infos.ip6 = (struct ndpi_ipv6hdr *)&packet[ip_offset];

    /*  Lvl 3   */

    pkt_infos.ip_size = pDyn1->capLength - pDyn1->descrLength - pkt_infos.ip_offset;

    if (ip_size < sizeof(pkt_infos.ip6->ip6_hdr)) {
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
                        uint8_t* & packet,
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

void NtDissector::processPacket(void * args,
                                void * header_tmp,
                                void * stream_id_tmp)
{
    FlowInfo flow = FlowInfo();
    NapatechReader * reader = (NapatechReader *) args;

    NtNetBuf_t * hNetBuffer = ((NtNetBuf_t *) header_tmp);

    NtDyn1Descr_t* pDyn1;

    struct ndpi_support pkt_infos;

    this->captured_stats.packets_captured++;

    // Updating time counters
    if(!this->captured_stats.nt_time_start)
    	this->captured_stats.nt_time_start = (uint64_t) NT_NET_GET_PKT_TIMESTAMP(* hNetBuffer);
    
    this->captured_stats.nt_time_end = (uint64_t) NT_NET_GET_PKT_TIMESTAMP(* hNetBuffer);
    
    // Checking idle flows
    reader->newPacket((void *)hNetBuffer);
    
    // Parsing packets
    this->getDyn(* hNetBuffer, flow, pDyn1, pkt_infos);
     
    this->captured_stats.packets_processed++;
    this->captured_stats.total_l4_data_len += pkt_infos.l4_len;
    
    if(this->searchVal(reader, flow, pkt_infos.tree_result, pkt_infos.hashed_index) != 0) {
        if(this->addVal(reader, flow, pkt_infos.flow_to_process, pkt_infos.hashed_index, pkt_infos.ndpi_src, pkt_infos.ndpi_dst) != 0) {
            this->captured_stats.discarded_bytes += pkt_infos.ip_size + pkt_infos.ip_offset;
            reader->setNewFlow(false);
        }
        else {
            this->captured_stats.total_flows_captured++;
            reader->setNewFlow(true);
        }
    } else {
        reader->setNewFlow(false);
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
    if (pkt_infos.flow_to_process->first_seen == 0) {
        pkt_infos.flow_to_process->first_seen = pkt_infos.time_ms;
    }
    pkt_infos.flow_to_process->last_seen = pkt_infos.time_ms;
    /* current packet is an TCP-ACK? */
    pkt_infos.flow_to_process->flow_ack_seen = flow.flow_ack_seen;

    /* TCP-FIN: indicates that at least one side wants to end the connection */
    if (flow.flow_fin_ack_seen != 0 && pkt_infos.flow_to_process->flow_fin_ack_seen == 0) {
        pkt_infos.flow_to_process->flow_fin_ack_seen = 1;
        tracer->traceEvent(4, "[%8llu, %4u] end of flow\n",
                                    this->captured_stats.packets_captured, pkt_infos.flow_to_process->flow_id);
        this->captured_stats.discarded_bytes += NT_NET_GET_PKT_CAP_LENGTH(* hNetBuffer);
        return;
    }
    
    this->printFlowInfos((Reader *) reader, pkt_infos.flow_to_process, pkt_infos.ip, pkt_infos.ip6, 
                            pkt_infos.ip_size, pkt_infos.ndpi_src, pkt_infos.ndpi_dst, pkt_infos.time_ms);
}

/* ********************************** */
