#include "ndpi_light_includes.h"


PacketDissector::PacketDissector()
{
    this->captured_stats.protos_cnt = nullptr;
}

/* ********************************** */

PacketDissector::PacketDissector(uint num)
{
    this->captured_stats.protos_cnt = new uint16_t[num + 1] ();
}

/* ********************************** */

PacketDissector::~PacketDissector()
{
    if(this == nullptr)
	    return;
        
    if(this->captured_stats.protos_cnt != nullptr)
        delete [] this->captured_stats.protos_cnt;
}

/* ********************************** */

void PacketDissector::updateTimerAndCntrs(FlowInfo& flow,
                      			            PacketInfo & pkt_infos)
{
    pkt_infos.flow_to_process->packets_processed++;
    /* update timestamps, important for timeout handling */
    if (pkt_infos.flow_to_process->first_seen == 0) {
        pkt_infos.flow_to_process->first_seen = pkt_infos.time_ms;
    }
    pkt_infos.flow_to_process->last_seen = pkt_infos.time_ms; 
    /* current packet is an TCP-ACK? */
    //pkt_infos.flow_to_process->flow_ack_seen = flow.flow_ack_seen;

    /* TCP-FIN: indicates that at least one side wants to end the connection */
    /*if (flow.flow_fin_ack_seen != 0 && pkt_infos.flow_to_process->flow_fin_ack_seen == 0) {
        pkt_infos.flow_to_process->flow_fin_ack_seen = 1;
        tracer->traceEvent(4, "[%8llu, %4u] end of flow\n",
                                    this->captured_stats.packets_captured, pkt_infos.flow_to_process->flow_id);
        this->captured_stats.discarded_bytes += pkt_infos.ip_offset + pkt_infos.eth_offset;
        return;
    }*/
}

/* ********************************** */

void PacketDissector::initProtosCnt(uint num)
{
    this->captured_stats.protos_cnt = new uint16_t[num + 1] ();
}

/* ********************************** */

void PacketDissector::printStats(Reader *reader)
{
    long long unsigned int avg_pkt_size = 0;
    long long unsigned int breed_stats[NUM_BREEDS] = { 0 };
    char buf[32];

    tracer->traceEvent(2, "\tTraffic statistics:\r\n");
    tracer->traceEvent(2, "\t\tEthernet bytes:             %-20llu (includes ethernet CRC/IFC/trailer)\n",
                            this->captured_stats.total_wire_bytes);
    tracer->traceEvent(2, "\t\tDiscarded bytes:            %-20llu\n",
                            this->captured_stats.discarded_bytes);
    tracer->traceEvent(2, "\t\tIP packets:                 %-20llu of %llu packets total\n",
                            this->captured_stats.ip_pkts,
                            this->captured_stats.packets_captured);
    tracer->traceEvent(2, "\t\tUnhandled IP packets:       %-20llu\n",
                            this->captured_stats.unhandled_packets);
    /* In order to prevent Floating point exception in case of no traffic*/
    if(this->captured_stats.ip_bytes && this->captured_stats.packets_captured)
        avg_pkt_size = this->captured_stats.ip_bytes/this->captured_stats.packets_captured;

    tracer->traceEvent(2, "\t\tIP bytes:                   %-20llu (avg pkt size %u bytes)\n",
                            this->captured_stats.ip_bytes, avg_pkt_size);

    tracer->traceEvent(2, "\t\tUnique flows:               %-20u\n", this->captured_stats.total_flows_captured);

    tracer->traceEvent(2, "\t\tTCP Packets:                %-20lu\n", this->captured_stats.tcp_pkts);
    tracer->traceEvent(2, "\t\tUDP Packets:                %-20lu\n", this->captured_stats.udp_pkts);

    tracer->traceEvent(2, "\t\tDetected flow protos:       %-20u\n", this->captured_stats.detected_flow_protocols);
    tracer->traceEvent(2, "\t\tGuessed flow protos:        %-20u\n", this->captured_stats.guessed_flow_protocols);
    tracer->traceEvent(2, "\t\tUnclassified flow protos:   %-20u\r\n", this->captured_stats.unclassified_flow_protocols);


    tracer->traceEvent(2, "\tDetected protocols:\r\n");

    for(u_int32_t i = 0; i <= ndpi_get_num_supported_protocols(reader->getNdpiStruct()); i++) {
        ndpi_protocol_breed_t breed = ndpi_get_proto_breed((reader->getNdpiStruct()), i);
        if(this->captured_stats.protos_cnt[i] > 0) {
            breed_stats[i] += this->captured_stats.protos_cnt[i];

            tracer->traceEvent(2, "\t\t%-20s flows: %-13u\r\n",
                ndpi_get_proto_name((reader->getNdpiStruct()), i), this->captured_stats.protos_cnt[i]);
        }
    }



    tracer->traceEvent(2, "\tProtocol statistics:\n");

    for(u_int32_t i = 0; i < NUM_BREEDS; i++) {
        if(breed_stats[i] > 0) {
        tracer->traceEvent(2, "\t\t%-20s flows: %-13u\n",
        ndpi_get_proto_breed_name(reader->getNdpiStruct(), ndpi_get_proto_breed(reader->getNdpiStruct(), i)),
        breed_stats[i]);
        }
    }
}

/* ********************************** */

int PacketDissector::searchVal(Reader * & reader,
                                FlowInfo& flow,
                                PacketInfo & pkt_infos)
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

    pkt_infos.hashed_index = (uint64_t) flow.hashval % reader->getMaxActiveFlows();
    pkt_infos.tree_result = ndpi_tfind(&flow, &reader->getActiveFlows()[pkt_infos.hashed_index], ndpi_workflow_node_cmp);

//    printf("%d, %d, %d\n", flow.hashval, reader->getMaxActiveFlows(), pkt_infos.hashed_index);
    if(pkt_infos.tree_result == nullptr)
        /*  Not Found   */
        return -1;
    else
        /*  Found   */
        return 0;
}

/* ********************************** */

int PacketDissector::addVal(Reader * & reader,
                        FlowInfo& flow,
                        PacketInfo & pkt_infos)
{
    if(reader->newFlow(pkt_infos.flow_to_process) != 0) 
        return -1;
    

    memcpy(pkt_infos.flow_to_process, &flow, sizeof(*pkt_infos.flow_to_process));
    pkt_infos.flow_to_process->flow_id = flow_id++;

    pkt_infos.flow_to_process->ndpi_flow = (struct ndpi_flow_struct *)ndpi_flow_malloc(SIZEOF_FLOW_STRUCT);
    if (pkt_infos.flow_to_process->ndpi_flow == nullptr) {
        tracer->traceEvent(0, "[%8llu, %4u] Not enough memory for flow struct\n",
                                this->captured_stats.packets_captured, pkt_infos.flow_to_process->flow_id);
        return -1;
    }

    memset(pkt_infos.flow_to_process->ndpi_flow, 0, SIZEOF_FLOW_STRUCT);

    pkt_infos.flow_to_process->ndpi_src = (struct ndpi_id_struct *)ndpi_calloc(1, SIZEOF_ID_STRUCT);
    if (pkt_infos.flow_to_process->ndpi_src == nullptr) {
        tracer->traceEvent(0, "[%8llu, %4u] Not enough memory for src id struct\n",
                                this->captured_stats.packets_captured, pkt_infos.flow_to_process->flow_id);
        return -1;
    }

    pkt_infos.flow_to_process->ndpi_dst = (struct ndpi_id_struct *)ndpi_calloc(1, SIZEOF_ID_STRUCT);
    if (pkt_infos.flow_to_process->ndpi_dst == nullptr) {
        tracer->traceEvent(0, "[%8llu, %4u] Not enough memory for dst id struct\n",
                                this->captured_stats.packets_captured, pkt_infos.flow_to_process->flow_id);
        return -1;
    }

    
    tracer->traceEvent(4, "[%8llu, %4u] new %sflow\n", this->captured_stats.packets_captured, 
                            pkt_infos.flow_to_process->flow_id, (pkt_infos.flow_to_process->is_midstream_flow != 0 ? "midstream-" : ""));

    if (ndpi_tsearch(pkt_infos.flow_to_process, &reader->getActiveFlows()[pkt_infos.hashed_index], ndpi_workflow_node_cmp) == nullptr) {
        /* Possible Leak */
        return -1;  
    }

    pkt_infos.ndpi_src = pkt_infos.flow_to_process->ndpi_src;
    pkt_infos.ndpi_dst = pkt_infos.flow_to_process->ndpi_dst;
    
    return 0;
}

/* ********************************** */

void PacketDissector::printFlowInfos(Reader * reader,
                                        PacketInfo & pkt_infos)
{
    if (pkt_infos.flow_to_process->ndpi_flow->num_processed_pkts == 0xFF) {
        return;
    } else if (pkt_infos.flow_to_process->ndpi_flow->num_processed_pkts == 0xFE) {
        /* last chance to guess something, better then nothing */
        uint8_t protocol_was_guessed = 0;
        pkt_infos.flow_to_process->guessed_protocol =
            ndpi_detection_giveup(reader->getNdpiStruct(),
                            pkt_infos.flow_to_process->ndpi_flow,
                            1, &protocol_was_guessed);
        pkt_infos.flow_to_process->ended_dpi = 1;

        if (protocol_was_guessed != 0) {
            /*  Protocol guessed    */
            tracer->traceEvent(3, "\t[%8llu, %4d][GUESSED] protocol: %s | app protocol: %s | category: %s\n",
                this->captured_stats.packets_captured,
                pkt_infos.flow_to_process->flow_id,
                ndpi_get_proto_name(reader->getNdpiStruct(), pkt_infos.flow_to_process->guessed_protocol.master_protocol),
                ndpi_get_proto_name(reader->getNdpiStruct(), pkt_infos.flow_to_process->guessed_protocol.app_protocol),
                ndpi_category_get_name(reader->getNdpiStruct(), pkt_infos.flow_to_process->guessed_protocol.category));
            
            this->captured_stats.protos_cnt[pkt_infos.flow_to_process->guessed_protocol.master_protocol]++;
            this->captured_stats.guessed_flow_protocols++;

            char src_addr_str[INET6_ADDRSTRLEN+1];
            char dst_addr_str[INET6_ADDRSTRLEN+1];
            char *tmp = ndpi_get_proto_breed_name(reader->getNdpiStruct(), 
                                                    ndpi_get_proto_breed(reader->getNdpiStruct(), 
                                                    pkt_infos.flow_to_process->detected_l7_protocol.master_protocol));
            pkt_infos.flow_to_process->ipTupleToString(src_addr_str, sizeof(src_addr_str), dst_addr_str, sizeof(dst_addr_str));
            
            if(strcmp(tmp, "Unsafe") == 0)
                tracer->traceEvent(1, "[%s flow] src ip: %s | dst ip: %s | src port: %u | dst port: %u\n", 
                                        tmp, src_addr_str, dst_addr_str, 
                                        pkt_infos.flow_to_process->src_port, pkt_infos.flow_to_process->dst_port);
            else
                tracer->traceEvent(3, "[%s flow] src ip: %s | dst ip: %s | src port: %u | dst port: %u\n", 
                                        tmp, src_addr_str, dst_addr_str, 
                                        pkt_infos.flow_to_process->src_port, pkt_infos.flow_to_process->dst_port);
        } else {
            tracer->traceEvent(3, "\t[%8llu, %d, %4d][FLOW NOT CLASSIFIED]\n",
                        this->captured_stats.packets_captured, pkt_infos.flow_to_process->flow_id);
            this->captured_stats.unclassified_flow_protocols++;
        }
    }

    pkt_infos.flow_to_process->detected_l7_protocol =
        ndpi_detection_process_packet(reader->getNdpiStruct(), pkt_infos.flow_to_process->ndpi_flow,
                        pkt_infos.ip != nullptr ? (uint8_t *)pkt_infos.ip : (uint8_t *)pkt_infos.ip6,
                        pkt_infos.ip_size, pkt_infos.time_ms, pkt_infos.ndpi_src, pkt_infos.ndpi_dst);

    if (ndpi_is_protocol_detected(reader->getNdpiStruct(), pkt_infos.flow_to_process->detected_l7_protocol) != 0 &&
        pkt_infos.flow_to_process->detection_completed == 0)
    {
		if (pkt_infos.flow_to_process->detected_l7_protocol.master_protocol != NDPI_PROTOCOL_UNKNOWN ||
		    pkt_infos.flow_to_process->detected_l7_protocol.app_protocol != NDPI_PROTOCOL_UNKNOWN) {
		    // Protocol detected
		    this->captured_stats.protos_cnt[pkt_infos.flow_to_process->detected_l7_protocol.master_protocol]++;
		    pkt_infos.flow_to_process->detection_completed = 1;
		    this->captured_stats.detected_flow_protocols++;
            pkt_infos.flow_to_process->ended_dpi = 1;

		    tracer->traceEvent(3, "\t[%8llu, %4d][DETECTED] protocol: %s | app protocol: %s | category: %s\n",
					    this->captured_stats.packets_captured,
                                    pkt_infos.flow_to_process->flow_id,
                                    ndpi_get_proto_name(reader->getNdpiStruct(), pkt_infos.flow_to_process->detected_l7_protocol.master_protocol),
                                    ndpi_get_proto_name(reader->getNdpiStruct(), pkt_infos.flow_to_process->detected_l7_protocol.app_protocol),
                                    ndpi_category_get_name(reader->getNdpiStruct(), pkt_infos.flow_to_process->detected_l7_protocol.category));

            char src_addr_str[INET6_ADDRSTRLEN+1];
            char dst_addr_str[INET6_ADDRSTRLEN+1];
            char *tmp = ndpi_get_proto_breed_name(reader->getNdpiStruct(), 
                                                    ndpi_get_proto_breed(reader->getNdpiStruct(), 
                                                    pkt_infos.flow_to_process->detected_l7_protocol.master_protocol));
            pkt_infos.flow_to_process->ipTupleToString(src_addr_str, sizeof(src_addr_str), dst_addr_str, sizeof(dst_addr_str));
            
            if(strcmp(tmp, "Unsafe") == 0)
                tracer->traceEvent(1, "[%s flow] src ip: %s | dst ip: %s | src port: %u | dst port: %u\n", 
                                        tmp, src_addr_str, dst_addr_str, 
                                        pkt_infos.flow_to_process->src_port, pkt_infos.flow_to_process->dst_port);
            else
                tracer->traceEvent(3, "[%s flow] src ip: %s | dst ip: %s | src port: %u | dst port: %u\n", 
                                        tmp, src_addr_str, dst_addr_str, 
                                        pkt_infos.flow_to_process->src_port, pkt_infos.flow_to_process->dst_port);
        }
    }
}

/* ********************************** */

void PacketDissector::processPacket(void * const args,
                                    void * header_tmp,
                                    void * packet_tmp)
{
    int status;
    FlowInfo flow = FlowInfo();
    Reader * reader = (Reader *) args;
    PacketInfo pkt_infos = PacketInfo();


    this->captured_stats.packets_captured++;

    /* Parsing the packet */
    status = this->parsePacket(flow, reader, header_tmp, packet_tmp, pkt_infos);

    this->captured_stats.packets_processed++;

    /* Switch the status received from parsePacket */
    switch(status) {
    case -1: /* Error case */
        return;

    case 0: /* No search inside the hashtable done */
        if(this->searchVal(reader, flow, pkt_infos) != 0) {
            if(this->addVal(reader, flow, pkt_infos) != 0) {
                this->captured_stats.discarded_bytes += pkt_infos.ip_offset + pkt_infos.eth_offset;
                return;
            }
            reader->setNewFlow(true);
            this->captured_stats.total_flows_captured++;
        } else {
            reader->setNewFlow(false);
            pkt_infos.flow_to_process = *(FlowInfo **)pkt_infos.tree_result;
        }
        break;

    case 1: /* Already done some search and value was not found */
        if(this->addVal(reader, flow, pkt_infos) != 0) {
            this->captured_stats.discarded_bytes += pkt_infos.ip_offset + pkt_infos.eth_offset;
            return;
        }
        reader->setNewFlow(true);
        this->captured_stats.total_flows_captured++;
        break;
        
    case 2: /* Already done some search and value was found */
        reader->setNewFlow(false);
        pkt_infos.flow_to_process = *(FlowInfo **)pkt_infos.tree_result;
    }

    this->updateTimerAndCntrs(flow, pkt_infos);

    if(pkt_infos.flow_to_process->ended_dpi)
        return;
    
    this->printFlowInfos((Reader *) reader, pkt_infos);
}

