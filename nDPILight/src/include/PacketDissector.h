#ifndef NDPILIGHT_PACKET_DISSECTOR_H
#define NDPILIGHT_PACKET_DISSECTOR_H


#include "ndpi_light_includes.h"


class PacketDissector {
    protected:
        class CaptureStats {
            public:
                unsigned long long int unhandled_packets;
                unsigned long long int packets_captured;
                unsigned long long int discarded_bytes;
                unsigned long long int ip_pkts;
                unsigned long long int ip_bytes;
                unsigned long long int tcp_pkts;
                unsigned long long int udp_pkts;
                
                unsigned long long int total_flows_captured;

                struct timeval pcap_start {0, 0}, pcap_end {0, 0};

                unsigned long long int nt_time_start, nt_time_end; 

                unsigned long long int packets_processed;
                unsigned long long int total_l4_data_len;
                unsigned long long int total_wire_bytes;

                unsigned long long int detected_flow_protocols;
                unsigned long long int guessed_flow_protocols;
                unsigned long long int unclassified_flow_protocols;

                uint16_t* protos_cnt;

        } captured_stats; 

    public:
        PacketDissector();
        PacketDissector(uint num);
        ~PacketDissector();


        virtual int parsePacket(FlowInfo flow
                                Reader * & const args,
                                void * header_tmp,
                                void * packet_tmp,
                                struct ndpi_support & pkt_infos) = 0;
	    /*  
         *  This function is called every time a new packets appears;
         *  it process all the packets, adding new flows, updating infos, ecc.  
         */
        void processPacket(void * args,
                            void * header,
                            void * packet);
        void initProtosCnt(uint num);
        void printStats(Reader* reader);
        
        /*  
         *  Prints all flow's infos  
         */                
        void printFlowInfos(Reader * reader,
                            FlowInfo * & flow_to_process,
                            const struct ndpi_iphdr * & ip,
                            struct ndpi_ipv6hdr * & ip6,
                            uint16_t& ip_size,
                            struct ndpi_id_struct * & ndpi_src,
                            struct ndpi_id_struct * & ndpi_dst,
                            uint64_t& time_ms);

	    unsigned long long int getPktsCaptured() { return captured_stats.packets_captured; };
        void incrPktsCaptured() { this->captured_stats.packets_captured++; };
        void incrUnhaPkts() { this->captured_stats.unhandled_packets++; };
	    void incrWireBytes(unsigned long long int bytes) { this->captured_stats.total_wire_bytes += bytes; };
};


#endif
