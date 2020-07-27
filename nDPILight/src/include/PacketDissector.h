
#include "ndpi_light_includes.h"


class PacketDissector {
private:
    unsigned long long int packets_captured = 0;
    unsigned long long int discarded_bytes = 0;
    unsigned long long int ip_pkts = 0;
    unsigned long long int ip_bytes = 0;
    unsigned long long int tcp_pkts = 0;
    unsigned long long int udp_pkts = 0;
    
    unsigned long long int total_flows_captured = 0;

    struct timeval pcap_start {0, 0}, pcap_end {0, 0};
    
public:
    void processPacket(uint8_t * args,
                        pcap_pkthdr const * header,
                        uint8_t const * packet);

    unsigned long long int getPktCaptured();
    unsigned long long int getDiscardedBytes();
    unsigned long long int getIpPkts();
    unsigned long long int getIpBytes();
    unsigned long long int getTcpPkts();
    unsigned long long int getUdpPkts();
    unsigned long long int getFlowsCount();
    time_t * getPcapStart();
    time_t * getPcapEnd();

private:
    int processL2(Reader * reader,
                pcap_pkthdr const * header,
                uint8_t const * packet,
                uint16_t& type,
                uint16_t& ip_size,
                uint16_t& ip_offset,
                const uint16_t& eth_offset,
                const struct ndpi_ethhdr * & ethernet);

    int setL2Ip(pcap_pkthdr const * header,
                uint8_t const * packet,
                uint16_t& type,
                uint16_t& ip_size,
                uint16_t& ip_offset,
                const struct ndpi_iphdr * & ip,
                struct ndpi_ipv6hdr * & ip6);

    int processL3(FlowInfo& flow,
                pcap_pkthdr const * header,
                uint8_t const * packet,
                uint16_t& type,
                uint16_t& ip_size,
                uint16_t& ip_offset,
                const struct ndpi_iphdr * & ip,
                struct ndpi_ipv6hdr * & ip6,
                const uint8_t * & l4_ptr,
                uint16_t& l4_len);

    int processL4(FlowInfo& flow,
                pcap_pkthdr const * header,
                uint8_t const * packet,
                const uint8_t * & l4_ptr,
                uint16_t& l4_len);

    int searchVal(Reader * & reader,
                FlowInfo& flow,
                void * & tree_result,
                struct ndpi_ipv6hdr * & ip6,
                size_t& hashed_index);

    int addVal(Reader * & reader,
                FlowInfo& flow,
                FlowInfo * & flow_to_process,
                size_t& hashed_index,
                struct ndpi_id_struct * & ndpi_src,
                struct ndpi_id_struct * & ndpi_dst);

    void printFlowInfos(Reader * & reader,
                        FlowInfo * & flow_to_process,
                        const struct ndpi_iphdr * & ip,
                        struct ndpi_ipv6hdr * & ip6,
                        uint16_t& ip_size,
                        struct ndpi_id_struct * & ndpi_src,
                        struct ndpi_id_struct * & ndpi_dst,
                        uint64_t& time_ms);

};

extern PacketDissector pkt_parser;

static void process_helper(uint8_t * const args,
                           pcap_pkthdr const * const header,
                           uint8_t const * const packet)
{
    pkt_parser.processPacket(args, header, packet);
};