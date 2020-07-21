//
// Created by matteo on 09/07/2020.
//


#include "ndpi_light_includes.h"


/* ********************************** */

static void ndpi_idle_scan_walker(void const * const A, ndpi_VISIT which, int depth, void * const user_data)
/*  Function used to search for idle flows  */
{
    PcapReader * const workflow = (PcapReader *)user_data;
    FlowInfo * const flow = *(FlowInfo **)A;

    (void)depth;

    if (workflow == nullptr || flow == nullptr) {
        return;
    }

    /* Is this limit needed?
    if (workflow->cur_idle_flows == MAX_IDLE_FLOWS_PER_THREAD) {
        return;
    }
    */

    if (which == ndpi_preorder || which == ndpi_leaf) {
        if ((flow->flow_fin_ack_seen == 1 && flow->flow_ack_seen == 1) ||
            flow->last_seen + MAX_IDLE_TIME < workflow->getLastTime())
            /*  New flow that need to be added to idle flows    */
        {
            char src_addr_str[INET6_ADDRSTRLEN+1];
            char dst_addr_str[INET6_ADDRSTRLEN+1];
            flow->ipTupleToString(src_addr_str, sizeof(src_addr_str), dst_addr_str, sizeof(dst_addr_str));
            workflow->incrCurIdleFlows();
            workflow->getNdpiFlowsIdle()[workflow->getCurIdleFlows()] = flow;
            workflow->incrTotalIdleFlows();
        }
    }
}

/* ********************************** */

static int ndpi_workflow_node_cmp(void const * const A, void const * const B)
/*  Checks if two nodes of the tree, A and B, are equals    */
{
    FlowInfo * const flow_info_a = (FlowInfo *)A;
    FlowInfo * const flow_info_b = (FlowInfo *)B;

    if(flow_info_a == nullptr || flow_info_b == nullptr) {
        return -1;
    }

    /*  Check hashval   */
    if (flow_info_a->hashval < flow_info_b->hashval) {
        return(-1);
    } else if (flow_info_a->hashval > flow_info_b->hashval) {
        return(1);
    }

    /*  Flows have the same hash, check l4_protocol */
    if (flow_info_a->l4_protocol < flow_info_b->l4_protocol) {
        return(-1);
    } else if (flow_info_a->l4_protocol > flow_info_b->l4_protocol) {
        return(1);
    }

    /*  Have same hashval and l4, check l3 ip   */
    if (flow_info_a->ipTuplesEqual(flow_info_b) != 0 &&
        flow_info_a->src_port == flow_info_b->src_port &&
        flow_info_a->dst_port == flow_info_b->dst_port)
    {
        return(0);
    }

    /*  Last check, l3 ip and port  */
    return flow_info_a->ipTuplesCompare(flow_info_b);
}

/* ********************************** */

/*  Constructors and Destructors    */
PcapReader::PcapReader() : file_or_device(nullptr)
{
    file_or_device = nullptr;
}

PcapReader::PcapReader(char const * const dst) : file_or_device(nullptr)
{
    file_or_device = dst;
}


PcapReader::~PcapReader()
/*  Destructor  */
{
    if(this->ndpi_struct != nullptr)
        free(ndpi_struct);
}

/* ********************************** */

void PcapReader::freeReader()
/*  Sort of destructor  */
{
    if(this == nullptr)
        return;

    if (this->pcap_handle != nullptr) {
        pcap_close(this->pcap_handle);
        this->pcap_handle = nullptr;
    }

    if (this->ndpi_struct != nullptr) {
        ndpi_exit_detection_module(this->ndpi_struct);
    }

    for(size_t i = 0; i < this->max_active_flows; i++) {
        ndpi_tdestroy(this->ndpi_flows_active[i], flowFreer);
    }

    if(this->ndpi_flows_active != nullptr)
        ndpi_free(this->ndpi_flows_active);
    if(this->ndpi_flows_idle != nullptr)
        ndpi_free(this->ndpi_flows_idle);
}

/* ********************************** */

int PcapReader::initModule()
/*  Initialize module's infos   */
{
    ndpi_init_prefs init_prefs = ndpi_no_prefs;
    this->ndpi_struct = ndpi_init_detection_module(init_prefs);
    if (this->ndpi_struct == nullptr) {
        return -1;
    }

    return 0;
}

/* ********************************** */

int PcapReader::initFileOrDevice()
/*  Initializing the pcap_handler, needed to read from a file or a device   */
{
    if (access(file_or_device, R_OK) != 0 && errno == ENOENT) {
        this->pcap_handle = pcap_open_live(file_or_device, /* 1536 */ 65535, 1, 250, pcap_error_buffer);
    } else {
        this->pcap_handle = pcap_open_offline_with_tstamp_precision(file_or_device, PCAP_TSTAMP_PRECISION_MICRO,
                                                                    pcap_error_buffer);
    }

    if(this->pcap_handle == nullptr) {
        tracer->traceEvent(0, "Error, pcap_open_live\
                                pcap_open_offline_with_tstamp_precision:\
                                \n%s\n\n", pcap_error_buffer);
        this->freeReader();
        return -1;
    }

    if(this->initModule() != 0) {
        tracer->traceEvent(0, "Error initializing detection module\n");
        this->freeReader();
        return -1;
    }

    if(this->initInfos() != 0) {
        tracer->traceEvent(0, "Error initializing structure infos\n");
        this->freeReader();
        return -1;
    }

    return 0;
}

/* ********************************** */

int PcapReader::initInfos()
/*  Initialize flow's infos */
{
    this->total_active_flows = 0; /* First initialize active flow's infos */
    this->max_active_flows = MAX_FLOW_ROOTS_PER_THREAD;
    this->ndpi_flows_active = (void **)ndpi_calloc(this->max_active_flows, sizeof(void *));
    if (this->ndpi_flows_active == nullptr) {
        return -1;
    }

    this->total_idle_flows = 0; /* Then initialize idle flow's infos */
    this->max_idle_flows = MAX_IDLE_FLOWS_PER_THREAD;
    this->ndpi_flows_idle = (void **)ndpi_calloc(this->max_idle_flows, sizeof(void *));
    if (this->ndpi_flows_idle == nullptr) {
        return -1;
    }

    NDPI_PROTOCOL_BITMASK protos; /* In the end initialize bitmask's infos */
    NDPI_BITMASK_SET_ALL(protos);
    ndpi_set_protocol_detection_bitmask2(this->ndpi_struct, &protos);
    ndpi_finalize_initalization(this->ndpi_struct);

    return 0;
}

/* ********************************** */

void PcapReader::printInfos()
/*  Prints infos about the packets and flows */
{
    tracer->traceEvent(2, "Total packets captured.: %llu\n", this->packets_captured);
    tracer->traceEvent(2, "Total packets processed: %llu\n", this->packets_processed);
    tracer->traceEvent(2, "Total layer4 data size.: %llu\n", this->total_l4_data_len);
    tracer->traceEvent(2, "Total flows captured...: %llu\n", this->total_active_flows);
    tracer->traceEvent(2, "Total flows timed out..: %llu\n", this->total_idle_flows);
    tracer->traceEvent(2, "Total flows detected...: %llu\r\n\r\n\r\n", this->detected_flow_protocols);

    this->freeReader();
}

/* ********************************** */

int PcapReader::startRead()
/*  Function used to start the pcap_loop    */
{
    if(this->pcap_handle != nullptr) {
        if (pcap_loop(this->pcap_handle, -1,
                      &process_helper, (uint8_t *) this) == PCAP_ERROR) {

            tracer->traceEvent(0, "Error while reading using Pcap: %s\n", pcap_geterr(this->pcap_handle));

            this->error_or_eof = 1;

            return -1;
        }
    }

    return -1;
}

/* ********************************** */

void PcapReader::stopRead()
/*  Function used to set pcap to nullptr    */
{
    if (this->pcap_handle != nullptr) {
        pcap_breakloop(this->pcap_handle);
    }
}

/* ********************************** */

int PcapReader::checkEnd()
{
    if(this->error_or_eof == 0)
        return 0;

    return -1;
}

/* ********************************** */

void PcapReader::checkForIdleFlows()
/*  Scan used to check if there are idle flows  */
{
    /*  Check if at least IDLE_SCAN_PERIOD passed since last scan   */
    if (this->last_idle_scan_time + IDLE_SCAN_PERIOD < this->last_time) {
        for (size_t idle_scan_index = 0; idle_scan_index < this->max_active_flows; ++idle_scan_index) {
            if(this->ndpi_flows_active[idle_scan_index] == nullptr)
                continue;

            ndpi_twalk(this->ndpi_flows_active[idle_scan_index], ndpi_idle_scan_walker, this);

            /*  Removes all idle flows that were copied into ndpi_flows_idle from the ndpi_twalk    */
            while (this->cur_idle_flows > 0) {
                /*  Get the flow    */
                FlowInfo * const tmp_f =
                        (FlowInfo *)this->ndpi_flows_idle[--this->cur_idle_flows];

                if(tmp_f == nullptr)
                    continue;

                if (tmp_f->flow_fin_ack_seen == 1) {
                    tracer->traceEvent(2, "[%8u] Freeing flow due to fin\n", tmp_f->flow_id);
                } else {
                    tracer->traceEvent(2, "[%8u] Freeing idle flow\n", tmp_f->flow_id);
                }

                /*  Removes it from the active flows    */
                ndpi_tdelete(tmp_f, &this->ndpi_flows_active[idle_scan_index],
                             ndpi_workflow_node_cmp);

                if(tmp_f != nullptr)
                    flowFreer(tmp_f);

                this->cur_active_flows--;
            }
        }

        this->last_idle_scan_time = this->last_time;
    }
}

/* ********************************** */

int PcapReader::processL2(pcap_pkthdr const * const header,
                          uint8_t const * const packet,
                          uint16_t& type,
                          uint16_t& ip_size,
                          uint16_t& ip_offset,
                          const uint16_t& eth_offset,
                          const struct ndpi_ethhdr * & ethernet
)
/*  Process datalink layer  */
{
    switch (pcap_datalink(this->pcap_handle)) {
        case DLT_NULL:
            /*  Loopback    */
            if (ntohl(*((uint32_t *)&packet[eth_offset])) == 0x00000002) {
                type = ETH_P_IP;
            } else {
                type = ETH_P_IPV6;
            }
            ip_offset = 4 + eth_offset;
            break;
        case DLT_EN10MB:
            /*  Ethernet    */
            if (header->len < sizeof(struct ndpi_ethhdr)) {
                tracer->traceEvent(1, "[%8llu] Ethernet packet too short - skipping\n", this->packets_captured);
                return -1;
            }
            ethernet = (struct ndpi_ethhdr *) &packet[eth_offset];
            ip_offset = sizeof(struct ndpi_ethhdr) + eth_offset;
            type = ntohs(ethernet->h_proto);
            switch (type) {
                case ETH_P_IP:
                    /* IPv4 */
                    if (header->len < sizeof(struct ndpi_ethhdr) + sizeof(struct ndpi_iphdr)) {
                        tracer->traceEvent(1, "[%8llu] Ethernet packet too short - skipping\n", this->packets_captured);
                        return -1;
                    }
                    break;

                case ETH_P_IPV6:
                    /* IPV6 */
                    if (header->len < sizeof(struct ndpi_ethhdr) + sizeof(struct ndpi_ipv6hdr)) {
                        tracer->traceEvent(1, "[%8llu] Ethernet packet too short - skipping\n", this->packets_captured);
                        return -1;
                    }
                    break;

                case ETH_P_ARP:
                    /* ARP */
                    return -1;

                default:
                    tracer->traceEvent(1, "[%8llu] Unknown Ethernet packet with \
                                            type %s - skipping\n", this->packets_captured, type);
                    return -1;
            }
            break;
        default:
            tracer->traceEvent(1, "[%8llu] Captured non IP/Ethernet packet with datalink \
                                    type %s - skipping\n", this->packets_captured, 
                                    pcap_datalink(this->pcap_handle));
            return -1;
    }

    return 0;
}

/* ********************************** */

int PcapReader::setL2Ip(pcap_pkthdr const * const header,
                        uint8_t const * const packet,
                        uint16_t& type,
                        uint16_t& ip_size,
                        uint16_t& ip_offset,
                        const struct ndpi_iphdr * & ip,
                        struct ndpi_ipv6hdr * & ip6
)
/*  Set l2 infos    */
{
    if (type == ETH_P_IP) {
        ip = (struct ndpi_iphdr *)&packet[ip_offset];
        ip6 = nullptr;
    } else if (type == ETH_P_IPV6) {
        ip = nullptr;
        ip6 = (struct ndpi_ipv6hdr *)&packet[ip_offset];
    } else {
        tracer->traceEvent(1, "[%8llu] Captured non IPv4/IPv6 packet with type \
                                     %s - skipping\n", this->packets_captured, 
                                    type); 
        return -1;
    }

    ip_size = header->len - ip_offset;

    if (type == ETH_P_IP && header->len >= ip_offset) {
        if (header->caplen < header->len) {
            tracer->traceEvent(0, "[%8llu] Captured packet size is smaller than packet size: %u < %u\n", 
                                    this->packets_captured, header->caplen, header->len); 
            return -1;
        }
    }

    return 0;
}

/* ********************************** */

int PcapReader::processL3(FlowInfo& flow,
                          pcap_pkthdr const * const header,
                          uint8_t const * const packet,
                          uint16_t& type,
                          uint16_t& ip_size,
                          uint16_t& ip_offset,
                          const struct ndpi_iphdr * & ip,
                          struct ndpi_ipv6hdr * & ip6,
                          const uint8_t * & l4_ptr,
                          uint16_t& l4_len)
/*  Process level3 of the packet    */
{
    if (ip != nullptr && ip->version == 4) {
        /*  IPv4    */
        if (ip_size < sizeof(*ip)) {
            tracer->traceEvent(0, "[%8llu] Packet smaller than IP4 header length: %u < %zu\n", 
                                    this->packets_captured, ip_size, sizeof(*ip)); 
            return -1;
        }

        flow.setFlowL3Type(4);

        if (ndpi_detection_get_l4((uint8_t*)ip, ip_size, &l4_ptr, &l4_len,
                                  &flow.l4_protocol, NDPI_DETECTION_ONLY_IPV4) != 0)
        {

            tracer->traceEvent(0, "[%8llu] nDPI IPv4/L4 payload detection failed, L4 length: %zu\n",
                                    this->packets_captured, ip_size - sizeof(*ip));
            return -1;
        }

        flow.ip_tuple.v4.src = ip->saddr;
        flow.ip_tuple.v4.dst = ip->daddr;

    } else if (ip6 != nullptr) {
        /*  IPv6    */
        if (ip_size < sizeof(ip6->ip6_hdr)) {
            tracer->traceEvent(0, "[%8llu] Packet smaller than IP6 header length: %u < %zu\n",
                                    this->packets_captured, ip_size, sizeof(ip6->ip6_hdr));
            return -1;
        }

        flow.setFlowL3Type(6);

        if (ndpi_detection_get_l4((uint8_t*)ip6, ip_size, &l4_ptr, &l4_len,
                                  &flow.l4_protocol, NDPI_DETECTION_ONLY_IPV6) != 0)
        {   
            tracer->traceEvent(0, "[%8llu] nDPI IPv6/L4 payload detection failed, L4 length: %zu\n",
                                    this->packets_captured, ip_size - sizeof(*ip));
            return -1;
        }

        flow.ip_tuple.v6.src[0] = ip6->ip6_src.u6_addr.u6_addr64[0];
        flow.ip_tuple.v6.src[1] = ip6->ip6_src.u6_addr.u6_addr64[1];
        flow.ip_tuple.v6.dst[0] = ip6->ip6_dst.u6_addr.u6_addr64[0];
        flow.ip_tuple.v6.dst[1] = ip6->ip6_dst.u6_addr.u6_addr64[1];
    } else {
        tracer->traceEvent(0, "[%8llu] Non IP/IPv6 protocol detected: 0x%X\n",
                                this->packets_captured, type);
        return -1;
    }

    return 0;
}

/* ********************************** */

int PcapReader::processL4(FlowInfo& flow,
                          pcap_pkthdr const * const header,
                          uint8_t const * const packet,
                          const uint8_t * & l4_ptr,
                          uint16_t& l4_len)
/*  Process level 4 of the packet   */
{
    if (flow.l4_protocol == IPPROTO_TCP) {
        /*  TCP   */
        const struct ndpi_tcphdr * tcp;

        if (header->len < (l4_ptr - packet) + sizeof(struct ndpi_tcphdr)) {
            tracer->traceEvent(0, "[%8llu] Malformed TCP packet, packet size smaller than expected: %u < %zu\n",
                                this->packets_captured, header->len, (l4_ptr - packet) + sizeof(struct ndpi_tcphdr));
            return -1;
        }

        tcp = (struct ndpi_tcphdr *)l4_ptr;

        /*  Checks the state of the flow */
        flow.is_midstream_flow = (tcp->syn == 0 ? 1 : 0);
        flow.flow_fin_ack_seen = (tcp->fin == 1 && tcp->ack == 1 ? 1 : 0);
        flow.flow_ack_seen = tcp->ack;
        flow.src_port = ntohs(tcp->source);
        flow.dst_port = ntohs(tcp->dest);

    } else if (flow.l4_protocol == IPPROTO_UDP) {
        /*  UDP   */
        const struct ndpi_udphdr * udp;


       
        if (header->len < (l4_ptr - packet) + sizeof(struct ndpi_udphdr)) {
            tracer->traceEvent(0, "[%8llu] Malformed UDP packet, packet size smaller than expected: %u < %zu\n",
                                this->packets_captured, header->len, (l4_ptr - packet) + sizeof(struct ndpi_udphdr));
            return -1;
        }
        udp = (struct ndpi_udphdr *)l4_ptr;
        flow.src_port = ntohs(udp->source);
        flow.dst_port = ntohs(udp->dest);
    }

    this->packets_processed++;
    this->total_l4_data_len += l4_len;

    return 0;
}

/* ********************************** */

int PcapReader::searchVal(FlowInfo& flow,
                          void * & tree_result,
                          struct ndpi_ipv6hdr * & ip6,
                          size_t& hashed_index,
                          int& direction_changed)
/* calculate flow hash for btree find, search(insert) */
{
    if (flow.getFlowL3Type() == 4) {
        /*  IPv4    */
        if (ndpi_flowv4_flow_hash(flow.l4_protocol, flow.ip_tuple.v4.src, flow.ip_tuple.v4.dst,
                                  flow.src_port, flow.dst_port, 0, 0,
                                  (uint8_t *)&flow.hashval, sizeof(flow.hashval)) != 0)
        {
            flow.hashval = flow.ip_tuple.v4.src + flow.ip_tuple.v4.dst; // fallback
        }
    } else if (flow.getFlowL3Type() == 6) {
        /*  IPv6    */
        if (ndpi_flowv6_flow_hash(flow.l4_protocol, &ip6->ip6_src, &ip6->ip6_dst,
                                  flow.src_port, flow.dst_port, 0, 0,
                                  (uint8_t *)&flow.hashval, sizeof(flow.hashval)) != 0)
        {
            flow.hashval = flow.ip_tuple.v6.src[0] + flow.ip_tuple.v6.src[1];
            flow.hashval += flow.ip_tuple.v6.dst[0] + flow.ip_tuple.v6.dst[1];
        }
    }
    flow.hashval += flow.l4_protocol + flow.src_port + flow.dst_port;

    hashed_index = flow.hashval % this->max_active_flows;
    tree_result = ndpi_tfind(&flow, &this->ndpi_flows_active[hashed_index], ndpi_workflow_node_cmp);

    if (tree_result == nullptr) {
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

        tree_result = ndpi_tfind(&flow, &this->ndpi_flows_active[hashed_index], ndpi_workflow_node_cmp);
        if (tree_result != nullptr) {
            direction_changed = 1;
        }

        flow.ip_tuple.v6.src[0] = orig_src_ip[0];
        flow.ip_tuple.v6.src[1] = orig_src_ip[1];
        flow.ip_tuple.v6.dst[0] = orig_dst_ip[0];
        flow.ip_tuple.v6.dst[1] = orig_dst_ip[1];
        flow.src_port = orig_src_port;
        flow.dst_port = orig_dst_port;
    }

    if(tree_result == nullptr)
        /*  Not Found   */
        return -1;
    else
        /*  Found   */
        return 0;
}

/* ********************************** */

int PcapReader::addVal(FlowInfo& flow,
                       FlowInfo * & flow_to_process,
                       size_t& hashed_index,
                       struct ndpi_id_struct * & ndpi_src,
                       struct ndpi_id_struct * & ndpi_dst)
/*  Add a new flow to the tree  */
{
    /* flow still not found, must be new */
    if (this->cur_active_flows == this->max_active_flows) {
        tracer->traceEvent(0, "[%8llu] max flows to track reached: %llu, idle: %llu\n",
                                this->packets_captured, this->max_active_flows, this->cur_idle_flows);
        return -1;
    }

    flow_to_process = (FlowInfo *)ndpi_malloc(sizeof(*flow_to_process));
    if (flow_to_process == nullptr) {
        tracer->traceEvent(0, "[%8llu] Not enough memory for flow info\n",
                                this->packets_captured);
        return -1;
    }

    this->cur_active_flows++;
    this->total_active_flows++;
    memcpy(flow_to_process, &flow, sizeof(*flow_to_process));
    flow_to_process->flow_id = flow_id++;

    flow_to_process->ndpi_flow = (struct ndpi_flow_struct *)ndpi_flow_malloc(SIZEOF_FLOW_STRUCT);
    if (flow_to_process->ndpi_flow == nullptr) {
        tracer->traceEvent(0, "[%8llu, %4u] Not enough memory for flow struct\n",
                                this->packets_captured, flow_to_process->flow_id);
        return -1;
    }

    memset(flow_to_process->ndpi_flow, 0, SIZEOF_FLOW_STRUCT);

    flow_to_process->ndpi_src = (struct ndpi_id_struct *)ndpi_calloc(1, SIZEOF_ID_STRUCT);
    if (flow_to_process->ndpi_src == nullptr) {
        tracer->traceEvent(0, "[%8llu, %4u] Not enough memory for src id struct\n",
                                this->packets_captured, flow_to_process->flow_id);
        return -1;
    }

    flow_to_process->ndpi_dst = (struct ndpi_id_struct *)ndpi_calloc(1, SIZEOF_ID_STRUCT);
    if (flow_to_process->ndpi_dst == nullptr) {
        tracer->traceEvent(0, "[%8llu, %4u] Not enough memory for dst id struct\n",
                                this->packets_captured, flow_to_process->flow_id);
        return -1;
    }

    
    tracer->traceEvent(2, "[%8llu, %4u] new %sflow\n", this->packets_captured, 
                            flow_to_process->flow_id, (flow_to_process->is_midstream_flow != 0 ? "midstream-" : ""));

    if (ndpi_tsearch(flow_to_process, &this->ndpi_flows_active[hashed_index], ndpi_workflow_node_cmp) == nullptr) {
        /* Possible Leak */
        return -1;
    }

    ndpi_src = flow_to_process->ndpi_src;
    ndpi_dst = flow_to_process->ndpi_dst;

    return 0;
}

void PcapReader::printFlowInfos(FlowInfo * & flow_to_process,
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
                ndpi_detection_giveup(this->ndpi_struct,
                                      flow_to_process->ndpi_flow,
                                      1, &protocol_was_guessed);
        if (protocol_was_guessed != 0) {
            /*  Protocol guessed    */


            tracer->traceEvent(2, "[%8llu, %4d][GUESSED] protocol: %s | app protocol: %s | category: %s\n",
                    this->packets_captured,
                    flow_to_process->flow_id,
                    ndpi_get_proto_name(this->ndpi_struct, flow_to_process->guessed_protocol.master_protocol),
                    ndpi_get_proto_name(this->ndpi_struct, flow_to_process->guessed_protocol.app_protocol),
                    ndpi_category_get_name(this->ndpi_struct, flow_to_process->guessed_protocol.category));
        } else {
            tracer->traceEvent(2, "[%8llu, %d, %4d][FLOW NOT CLASSIFIED]\n",
                                    this->packets_captured, flow_to_process->flow_id);
        }
    }

    flow_to_process->detected_l7_protocol =
            ndpi_detection_process_packet(this->ndpi_struct, flow_to_process->ndpi_flow,
                                          ip != nullptr ? (uint8_t *)ip : (uint8_t *)ip6,
                                          ip_size, time_ms, ndpi_src, ndpi_dst);

    if (ndpi_is_protocol_detected(this->ndpi_struct,
                                  flow_to_process->detected_l7_protocol) != 0 &&
        flow_to_process->detection_completed == 0)
    {
        if (flow_to_process->detected_l7_protocol.master_protocol != NDPI_PROTOCOL_UNKNOWN ||
            flow_to_process->detected_l7_protocol.app_protocol != NDPI_PROTOCOL_UNKNOWN) {
            //Protocol detected

            flow_to_process->detection_completed = 1;
            this->detected_flow_protocols++;
            tracer->traceEvent(2, "[%8llu, %4d][DETECTED] protocol: %s | app protocol: %s | category: %s\n",
                                    this->packets_captured,
                                    flow_to_process->flow_id,
                                    ndpi_get_proto_name(this->ndpi_struct, flow_to_process->detected_l7_protocol.master_protocol),
                                    ndpi_get_proto_name(this->ndpi_struct, flow_to_process->detected_l7_protocol.app_protocol),
                                    ndpi_category_get_name(this->ndpi_struct, flow_to_process->detected_l7_protocol.category));
        }
    }
}

/* ********************************** */

void PcapReader::processPacket(uint8_t * const args,
                               pcap_pkthdr const * const header,
                               uint8_t const * const packet)
/*  This function is called every time a new packets appears;
 *  it process all the packets, adding new flows, updating infos, ecc.  */
{
    FlowInfo flow = FlowInfo();

    size_t hashed_index = 0;
    void * tree_result = nullptr;
    FlowInfo * flow_to_process = nullptr;

    int direction_changed = 0;
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

    int thread_index = INITIAL_THREAD_HASH; /* generated with `dd if=/dev/random bs=1024 count=1 |& hd' */


    this->packets_captured++;
    time_ms = ((uint64_t) header->ts.tv_sec) * TICK_RESOLUTION + header->ts.tv_usec / (1000000 / TICK_RESOLUTION);
    this->last_time = time_ms;

/*  Scan done every 10000 ms more or less   */
    this->checkForIdleFlows();

/*  Process L2  */
    if(this->processL2(header, packet, type, ip_size, ip_offset, eth_offset, ethernet) != 0)
        return;

    if(this->setL2Ip(header, packet, type, ip_size, ip_offset, ip, ip6) != 0)
        return;

/*  Process L3  */
    if(this->processL3(flow, header, packet, type, ip_size, ip_offset, ip, ip6, l4_ptr, l4_len) != 0)
        return;

/*  Process L4  */
    if(this->processL4(flow, header, packet, l4_ptr, l4_len) != 0)
        return;

    if(this->searchVal(flow, tree_result, ip6, hashed_index, direction_changed) != 0) {
        if(this->addVal(flow, flow_to_process, hashed_index, ndpi_src, ndpi_dst) != 0)
            return;
    } else {
        flow_to_process = *(FlowInfo **)tree_result;

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
        tracer->traceEvent(2, "[%8llu, %4u] end of flow\n",
                                    this->packets_captured, flow_to_process->flow_id);
        return;
    }

    this->printFlowInfos(flow_to_process, ip, ip6, ip_size, ndpi_src, ndpi_dst, time_ms);
}

/* ********************************** */
/*  GETTERS AND SETTERS */

void PcapReader::incrTotalIdleFlows()
{
    this->total_idle_flows++;
}

void PcapReader::incrCurIdleFlows()
{
    this->cur_idle_flows++;
}

uint64_t PcapReader::getLastTime()
{
    return this->last_time;
}

void **PcapReader::getNdpiFlowsIdle()
{
    return this->ndpi_flows_idle;
}

unsigned long long int PcapReader::getCurIdleFlows()
{
    return this->cur_idle_flows;
}

/* ********************************** */