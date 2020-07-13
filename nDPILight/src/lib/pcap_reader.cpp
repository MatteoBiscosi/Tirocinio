//
// Created by matteo on 09/07/2020.
//

#include <ndpi_light_includes.h>
#include <pcap_reader.h>

/* ********************************** */

/*  Constructors    */
PcapReader::PcapReader() : file_or_device(nullptr)
{
    file_or_device = nullptr;
}

PcapReader::PcapReader(char const * const dst) : file_or_device(nullptr)
{
    file_or_device = dst;
}

/* ********************************** */

void PcapReader::freeReader()
/*  Sort of destructor  */
{
    if (this->pcap_handle != nullptr) {
        pcap_close(this->pcap_handle);
        this->pcap_handle = nullptr;
    }

    if (this->ndpi_struct != nullptr) {
        ndpi_exit_detection_module(this->ndpi_struct);
    }
    for(size_t i = 0; i < this->max_active_flows; i++) {
        ndpi_tdestroy(this->ndpi_flows_active[i], ndpi_flow_info_freer);
    }
    ndpi_free(this->ndpi_flows_active);
    ndpi_free(this->ndpi_flows_idle);
    ndpi_free(this);
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
        std::cerr << "Error, pcap_open_live / pcap_open_offline_with_tstamp_precision: "
                  << pcap_error_buffer << "\n";
        this->freeReader();
        return -1;
    }

    if(this->initModule() != 0) {
        std::cerr << "Error initializing detection module\n";
        this->freeReader();
        return -1;
    }

    if(this->initInfos() != 0) {
        std::cerr << "Error initializing structure infos\n";
        this->freeReader();
        return -1;
    }
}

/* ********************************** */

int PcapReader::initInfos()
/*  Initialize flow's infos */
{
    this->total_active_flows = 0; /* First initialize active flow's infos */
    this->max_active_flows = MAX_FLOW_ROOTS_PER_THREAD;
    this->ndpi_flows_active = (void **)ndpi_calloc(this->max_idle_flows, sizeof(void *))
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
}

/* ********************************** */

void PcapReader::printInfos()
/*  Prints infos about the packets and flows */
{
    std::cout << "Total packets captured.: " << this->packets_captured << "\n";
    std::cout << "Total packets processed: " << this->packets_processed << "\n";
    std::cout << "Total layer4 data size.: " << this->total_l4_data_len << "\n";
    std::cout << "Total flows captured...: " << this->total_active_flows << "\n";
    std::cout << "Total flows timed out..: " << this->total_idle_flows << "\n";
    std::cout << "Total flows detected...: " << this->detected_flow_protocols << "\n";
}

/* ********************************** */

static void process_helper(uint8_t * const args,
                           pcap_pkthdr const * const header,
                           uint8_t const * const packet)
/*  Utility function used to call class-specific process packet */
{
    auto * const reader_thread = (PcapReader *) args;
    reader_thread->processPacket(nullptr, header, packet);
}

/* ********************************** */

int PcapReader::startRead()
/*  Function used to start the pcap_loop    */
{
    if(this->pcap_handle != nullptr) {
        if (pcap_loop(this->pcap_handle, -1,
                      &process_helper, (uint8_t *) this) == PCAP_ERROR) {

            std::cerr << "Error while reading using Pcap: "
                 << pcap_geterr(this->pcap_handle) << "\n";

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
        this->pcap_handle = nullptr;
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

static void ndpi_idle_scan_walker(void const * const A, ndpi_VISIT which, int depth, void * const user_data)
/*  Function used to search for idle flows  */
{
    auto * const workflow = (PcapReader *)user_data;
    auto * const flow = *(FlowInfo **)A;

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
    auto * const flow_info_a = (FlowInfo *)A;
    auto * const flow_info_b = (FlowInfo *)B;

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

void PcapReader::checkForIdleFlows()
/*  Scan used to check if there are idle flows  */
{
    /*  Check if at least IDLE_SCAN_PERIOD passed since last scan   */
    if (this->last_idle_scan_time + IDLE_SCAN_PERIOD < this->last_time) {
        for (size_t idle_scan_index = 0; idle_scan_index < this->max_active_flows; ++idle_scan_index) {
            ndpi_twalk(this->ndpi_flows_active[idle_scan_index], ndpi_idle_scan_walker, this);

            /*  Removes all idle flows that were copied into ndpi_flows_idle from the ndpi_twalk    */
            while (this->cur_idle_flows > 0) {
                /*  Get the flow    */
                auto * const tmp_f =
                        (FlowInfo *)this->ndpi_flows_idle[--this->cur_idle_flows];
                if (tmp_f->flow_fin_ack_seen == 1) {
                    std::cout << "Free fin flow with id " << tmp_f->flow_id << "\n";
                } else {
                    std::cout << "Free idle flow with id " << tmp_f->flow_id << "\n";
                }

                /*  Removes it from the active flows    */
                ndpi_tdelete(tmp_f, &this->ndpi_flows_active[idle_scan_index],
                                 ndpi_workflow_node_cmp);
                tmp_f->infoFreer();
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
                           const struct ndpi_ethhdr * ethernet
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
            std::cerr << "[" << this->packets_captured << "] Ethernet packet too short - skipping\n";
            return -1;
        }
        ethernet = (struct ndpi_ethhdr *) &packet[eth_offset];
        ip_offset = sizeof(struct ndpi_ethhdr) + eth_offset;
        type = ntohs(ethernet->h_proto);
        switch (type) {
        case ETH_P_IP:
            /* IPv4 */
            if (header->len < sizeof(struct ndpi_ethhdr) + sizeof(struct ndpi_iphdr)) {
                std::cerr << "[" << this->packets_captured << "] Ethernet packet too short - skipping\n";
                return -1;
            }
            break;

        case ETH_P_IPV6:
            /* IPV6 */
            if (header->len < sizeof(struct ndpi_ethhdr) + sizeof(struct ndpi_ipv6hdr)) {
                std::cerr << "[" << this->packets_captured << "] Ethernet packet too short - skipping\n";
                return -1;
            }
            break;

        case ETH_P_ARP:
            /* ARP */
            return -1;

        default:
            std::cerr << "[" << this->packets_captured << "] Unknown Ethernet packet with type "
            << type << " - skipping\n";
            return -1;
        }
        break;
    default:
        std::cerr << "[" << this->packets_captured
                  << "] Captured non IP/Ethernet packet with datalink type "
                  << pcap_datalink(this->pcap_handle) << " - skipping\n";
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
                         const struct ndpi_iphdr * ip,
                         struct ndpi_ipv6hdr * ip6
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
        std::cerr << "[" << this->packets_captured << "] Captured non IPv4/IPv6 packet with type "
                  << type << " - skipping\n";
        return -1;
    }

    ip_size = header->len - ip_offset;

    if (type == ETH_P_IP && header->len >= ip_offset) {
        if (header->caplen < header->len) {
            std::cerr << "[" << this->packets_captured
                      << "] Captured packet size is smaller than packet size: "
                      << header->caplen << " < " << header->len << "\n";
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
                           const struct ndpi_iphdr * ip,
                           struct ndpi_ipv6hdr * ip6,
                           const uint8_t * l4_ptr,
                           uint16_t& l4_len)
/*  Process level3 of the packet    */
{
    if (ip != nullptr && ip->version == 4) {
        /*  IPv4    */
        if (ip_size < sizeof(*ip)) {
            std::cerr << "[" << this->packets_captured
                      << "] Packet smaller than IP4 header length: "
                      << ip_size << " < " << sizeof(*ip) << "\n";
            return -1;
        }

        flow.setFlowL3Type(4);

        if (ndpi_detection_get_l4((uint8_t*)ip, ip_size, &l4_ptr, &l4_len,
                                  &flow.l4_protocol, NDPI_DETECTION_ONLY_IPV4) != 0)
        {
            std::cerr << "[" << this->packets_captured
                      << "] nDPI IPv4/L4 payload detection failed, L4 length: "
                      << ip_size - sizeof(*ip) << "\n";
            return -1;
        }

        flow.ip_tuple.v4.src = ip->saddr;
        flow.ip_tuple.v4.dst = ip->daddr;

    } else if (ip6 != nullptr) {
        /*  IPv6    */
        if (ip_size < sizeof(ip6->ip6_hdr)) {
            std::cerr << "[" << this->packets_captured
                      << "] Packet smaller than IP6 header length: "
                      << ip_size << " < " << sizeof(ip6->ip6_hdr) << "\n";
            return -1;
        }

        flow.setFlowL3Type(6);

        if (ndpi_detection_get_l4((uint8_t*)ip6, ip_size, &l4_ptr, &l4_len,
                                  &flow.l4_protocol, NDPI_DETECTION_ONLY_IPV6) != 0)
        {
            std::cerr << "[" << this->packets_captured
                      << "] nDPI IPv6/L4 payload detection failed, L4 length: "
                      << ip_size - sizeof(*ip) << "\n";
            return -1;
        }

        flow.ip_tuple.v6.src[0] = ip6->ip6_src.u6_addr.u6_addr64[0];
        flow.ip_tuple.v6.src[1] = ip6->ip6_src.u6_addr.u6_addr64[1];
        flow.ip_tuple.v6.dst[0] = ip6->ip6_dst.u6_addr.u6_addr64[0];
        flow.ip_tuple.v6.dst[1] = ip6->ip6_dst.u6_addr.u6_addr64[1];
    } else {
        std::cerr << "[" << this->packets_captured
                  << "] Non IP/IPv6 protocol detected: "
                  << type << "\n";
        return -1;
    }

    return 0;
}

/* ********************************** */

int PcapReader::processL4(FlowInfo& flow,
                          pcap_pkthdr const * const header,
                          uint8_t const * const packet,
                          const uint8_t * l4_ptr,
                          uint16_t& l4_len)
/*  Process level 4 of the packet   */
{
    if (flow.l4_protocol == IPPROTO_TCP) {
        /*  TCP   */
        const struct ndpi_tcphdr * tcp;

        if (header->len < (l4_ptr - packet) + sizeof(struct ndpi_tcphdr)) {
            std::cerr << "[" << this->packets_captured
                      << "] Malformed TCP packet, packet size smaller than expected: "
                      << header->len << " < "
                      << (l4_ptr - packet) + sizeof(struct ndpi_tcphdr) <<"\n";
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
            std::cerr << "[" << this->packets_captured
                      << "] Malformed TCP packet, packet size smaller than expected: "
                      << header->len << " < "
                      << (l4_ptr - packet) + sizeof(struct ndpi_udphdr) <<"\n";
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
                          void * tree_result,
                          struct ndpi_ipv6hdr * ip6,
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
                       FlowInfo * flow_to_process,
                       size_t& hashed_index,
                       struct ndpi_id_struct * ndpi_src,
                       struct ndpi_id_struct * ndpi_dst)
/*  Add a new flow to the tree  */
{
    /* flow still not found, must be new */
    if (this->cur_active_flows == this->max_active_flows) {
        std::cerr << "[" << this->packets_captured
                  << "] max flows to track reached: "
                  << this->max_active_flows << ", idle: "
                  << this->cur_idle_flows <<"\n";
        return -1;
    }

    flow_to_process = (FlowInfo *)ndpi_malloc(sizeof(*flow_to_process));
    if (flow_to_process == nullptr) {
        std::cerr << "[" << this->packets_captured
                  << "] Not enough memory for flow info\n";
        return -1;
    }

    this->cur_active_flows++;
    this->total_active_flows++;
    memcpy(flow_to_process, &flow, sizeof(*flow_to_process));
    flow_to_process->flow_id = flow_id++;

    flow_to_process->ndpi_flow = (struct ndpi_flow_struct *)ndpi_flow_malloc(SIZEOF_FLOW_STRUCT);
    if (flow_to_process->ndpi_flow == nullptr) {
        std::cerr << "[" << this->packets_captured
                  << ", " << flow_to_process->flow_id << ", "
                  << "] Not enough memory for flow struct\n"

                  << this->cur_idle_flows <<"\n";
        return -1;
    }

    memset(flow_to_process->ndpi_flow, 0, SIZEOF_FLOW_STRUCT);

    flow_to_process->ndpi_src = (struct ndpi_id_struct *)ndpi_calloc(1, SIZEOF_ID_STRUCT);
    if (flow_to_process->ndpi_src == nullptr) {
        std::cerr << "[" << this->packets_captured
                  << ", " << flow_to_process->flow_id << ", "
                  << "] Not enough memory for src id struct\n"

                  << this->cur_idle_flows <<"\n";
        return -1;
    }

    flow_to_process->ndpi_dst = (struct ndpi_id_struct *)ndpi_calloc(1, SIZEOF_ID_STRUCT);
    if (flow_to_process->ndpi_dst == nullptr) {
        std::cerr << "[" << this->packets_captured
                  << ", " << flow_to_process->flow_id << ", "
                  << "] Not enough memory for dst id struct\n"

                  << this->cur_idle_flows <<"\n";
        return -1;
    }

    std::cout << "[" << this->packets_captured << ", "
              << flow_to_process->flow_id << "] new "
              << (flow_to_process->is_midstream_flow != 0 ? "midstream-" : "") << "flow\n";

    if (ndpi_tsearch(flow_to_process, &this->ndpi_flows_active[hashed_index], ndpi_workflow_node_cmp) == nullptr) {
        /* Possible Leak, but should not happen as we'd abort earlier. */
        return -1;
    }

    ndpi_src = flow_to_process->ndpi_src;
    ndpi_dst = flow_to_process->ndpi_dst;

    return 0;
}

void PcapReader::printFlowInfos(FlowInfo * flow_to_process,
                                const struct ndpi_iphdr * ip,
                                struct ndpi_ipv6hdr * ip6,
                                uint16_t& ip_size,
                                struct ndpi_id_struct * ndpi_src,
                                struct ndpi_id_struct * ndpi_dst,
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
            std::cout << "[" << this->packets_captured
                      << ", " << flow_to_process->flow_id
                      << "][GUESSED] protocol: "
                      << ndpi_get_proto_name(this->ndpi_struct, flow_to_process->guessed_protocol.master_protocol)
                      << " | app protocol: "
                      << ndpi_get_proto_name(this->ndpi_struct, flow_to_process->guessed_protocol.app_protocol)
                      << " | category: "
                      << ndpi_category_get_name(this->ndpi_struct, flow_to_process->guessed_protocol.category)
                      << "\n";
        } else {
            std::cout << "[" << this->packets_captured
                      << ", " << flow_to_process->flow_id
                      << "][FLOW NOT CLASSIFIED]\n";
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
            std::cout << "[" << this->packets_captured
                      << ", " << flow_to_process->flow_id
                      << "][DETECTED] protocol: "
                      << ndpi_get_proto_name(this->ndpi_struct, flow_to_process->detected_l7_protocol.master_protocol)
                      << " | app protocol: "
                      << ndpi_get_proto_name(this->ndpi_struct, flow_to_process->detected_l7_protocol.app_protocol)
                      << " | category: "
                      << ndpi_category_get_name(this->ndpi_struct, flow_to_process->detected_l7_protocol.category)
                      << "\n";
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
    FlowInfo flow;

    size_t hashed_index;
    void * tree_result;
    FlowInfo * flow_to_process;

    int direction_changed = 0;
    struct ndpi_id_struct * ndpi_src;
    struct ndpi_id_struct * ndpi_dst;

    const struct ndpi_ethhdr * ethernet;
    const struct ndpi_iphdr * ip;
    struct ndpi_ipv6hdr * ip6;

    uint64_t time_ms;
    const uint16_t eth_offset = 0;
    uint16_t ip_offset;
    uint16_t ip_size;
    uint16_t type;

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
        std::cout << "[" << this->packets_captured << ", "
                  << flow_to_process->flow_id << "] end of flow\n";
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