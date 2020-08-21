#include ndpi_light_includes.h


PacketDissector::PacketDissector()
{
    this->pcap_start {0, 0};
    this->pcap_end {0, 0};
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

void initProtosCnt(uint num)
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