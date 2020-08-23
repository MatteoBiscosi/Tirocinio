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
    tracer->traceEvent(2, "\t\tUnhandled IP packets:                 %-20llu\n",
                            this->captured_stats.unhandled_packets);
    /* In order to prevent Floating point exception in case of no traffic*/
    if(this->captured_stats.ip_bytes && this->captured_stats.packets_captured)
        avg_pkt_size = this->captured_stats.ip_bytes/this->captured_stats.packets_captured;

    tracer->traceEvent(2, "\t\tIP bytes:                   %-20llu (avg pkt size %u bytes)\n",
                            this->captured_stats.ip_bytes, avg_pkt_size);

    tracer->traceEvent(2, "\t\tUnique flows:               %-20u\n", this->captured_stats.total_flows_captured);

    tracer->traceEvent(2, "\t\tTCP Packets:                %-20lu\n", this->captured_stats.tcp_pkts);
    tracer->traceEvent(2, "\t\tUDP Packets:                %-20lu\n", this->captured_stats.udp_pkts);

    char when[64];
    struct tm result;

    strftime(when, sizeof(when), "%d/%b/%Y %H:%M:%S", localtime_r(&this->captured_stats.pcap_start.tv_sec, &result));
    tracer->traceEvent(2, "\t\tAnalysis begin:             %s\n", when);

    strftime(when, sizeof(when), "%d/%b/%Y %H:%M:%S", localtime_r(&this->captured_stats.pcap_end.tv_sec, &result));
    tracer->traceEvent(2, "\t\tAnalysis end:               %s\n", when);

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

void PacketDissector::printFlowInfos(Reader * reader,
                                    FlowInfo * & flow_to_process,
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
                ndpi_detection_giveup(reader->getNdpiStruct(),
                                      flow_to_process->ndpi_flow,
                                      1, &protocol_was_guessed);
        if (protocol_was_guessed != 0) {
            /*  Protocol guessed    */
            tracer->traceEvent(3, "\t[%8llu, %4d][GUESSED] protocol: %s | app protocol: %s | category: %s\n",
                    this->captured_stats.packets_captured,
                    flow_to_process->flow_id,
                    ndpi_get_proto_name(reader->getNdpiStruct(), flow_to_process->guessed_protocol.master_protocol),
                    ndpi_get_proto_name(reader->getNdpiStruct(), flow_to_process->guessed_protocol.app_protocol),
                    ndpi_category_get_name(reader->getNdpiStruct(), flow_to_process->guessed_protocol.category));
            
            this->captured_stats.protos_cnt[flow_to_process->guessed_protocol.master_protocol]++;
            this->captured_stats.guessed_flow_protocols++;

            char *tmp = ndpi_get_proto_breed_name(reader->getNdpiStruct(), ndpi_get_proto_breed(reader->getNdpiStruct(), flow_to_process->detected_l7_protocol.master_protocol));
            if(flow_to_process->l3_type == L3_IP) {
                if(strcmp(tmp, "Unsafe") == 0)
                    tracer->traceEvent(1, " [%s flow] src ip: %lu | port: %u\n", 
                                            tmp, flow_to_process->ip_tuple.v4.src, flow_to_process->dst_port);
                else
                    tracer->traceEvent(3, " [%s flow] src ip: %lu | port: %u\n", 
                                            tmp, flow_to_process->ip_tuple.v4.src, flow_to_process->dst_port);
            }
            else
            {
                if(strcmp(tmp, "Unsafe") == 0)
                    tracer->traceEvent(1, " [%s flow] src ip: %lu%lu | port: %u\n", 
                                            tmp, flow_to_process->ip_tuple.v6.src[0], flow_to_process->ip_tuple.v6.src[1], flow_to_process->dst_port);
                else
                    tracer->traceEvent(1, " [%s flow] src ip: %lu | port: %u\n", 
                                            tmp, flow_to_process->ip_tuple.v4.src, flow_to_process->dst_port);
            }
        } else {
            tracer->traceEvent(3, "\t[%8llu, %d, %4d][FLOW NOT CLASSIFIED]\n",
                                    this->captured_stats.packets_captured, flow_to_process->flow_id);
            this->captured_stats.unclassified_flow_protocols++;
        }
    }

    flow_to_process->detected_l7_protocol =
            ndpi_detection_process_packet(reader->getNdpiStruct(), flow_to_process->ndpi_flow,
                                          ip != nullptr ? (uint8_t *)ip : (uint8_t *)ip6,
                                          ip_size, time_ms, ndpi_src, ndpi_dst);

    if (ndpi_is_protocol_detected(reader->getNdpiStruct(),
                                  flow_to_process->detected_l7_protocol) != 0 &&
        flow_to_process->detection_completed == 0)
    {
        if (flow_to_process->detected_l7_protocol.master_protocol != NDPI_PROTOCOL_UNKNOWN ||
            flow_to_process->detected_l7_protocol.app_protocol != NDPI_PROTOCOL_UNKNOWN) {
            //Protocol detected
            this->captured_stats.protos_cnt[flow_to_process->detected_l7_protocol.master_protocol]++;
            flow_to_process->detection_completed = 1;
            this->captured_stats.detected_flow_protocols++;
            tracer->traceEvent(3, "\t[%8llu, %4d][DETECTED] protocol: %s | app protocol: %s | category: %s\n",
                                    this->captured_stats.packets_captured,
                                    flow_to_process->flow_id,
                                    ndpi_get_proto_name(reader->getNdpiStruct(), flow_to_process->detected_l7_protocol.master_protocol),
                                    ndpi_get_proto_name(reader->getNdpiStruct(), flow_to_process->detected_l7_protocol.app_protocol),
                                    ndpi_category_get_name(reader->getNdpiStruct(), flow_to_process->detected_l7_protocol.category));
        }

        char *tmp = ndpi_get_proto_breed_name(reader->getNdpiStruct(), ndpi_get_proto_breed(reader->getNdpiStruct(), flow_to_process->detected_l7_protocol.master_protocol));
        if(flow_to_process->l3_type == L3_IP) {
            if(strcmp(tmp, "Unsafe") == 0)
                tracer->traceEvent(1, " [%s flow] src ip: %lu | port: %u\n", 
                                        tmp, flow_to_process->ip_tuple.v4.src, flow_to_process->dst_port);
            else
                tracer->traceEvent(3, " [%s flow] src ip: %lu | port: %u\n", 
                                        tmp, flow_to_process->ip_tuple.v4.src, flow_to_process->dst_port);
        }
        else
        {
            if(strcmp(tmp, "Unsafe") == 0)
                tracer->traceEvent(1, " [%s flow] src ip: %lu%lu | port: %u\n", 
                                        tmp, flow_to_process->ip_tuple.v6.src[0], flow_to_process->ip_tuple.v6.src[1], flow_to_process->dst_port);
            else
                tracer->traceEvent(1, " [%s flow] src ip: %lu | port: %u\n", 
                                        tmp, flow_to_process->ip_tuple.v4.src, flow_to_process->dst_port);
        }
    }
}

/* ********************************** */
