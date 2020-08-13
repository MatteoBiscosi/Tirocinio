#ifndef NDPILIGHT_NT_DISSECTOR_H
#define NDPILIGHT_NT_DISSECTOR_H


#include "ndpi_light_includes.h"


class NtDissector : public PacketDissector{
    private:
        NtDyn1Descr_t* pDyn1;
        uint8_t* packet;

    public:
	void processPacket(void *, void *, void *);    

    private:
	void DumpL4(NtDyn1Descr_t * &);
	void DumpIPv4(NtDyn1Descr_t * &);
	void DumpIPv6(NtDyn1Descr_t * &);
	void getDyn(NtNetBuf_s * &);
	int processL2(Reader * const reader,
                                NtNetBuf_t& hNetBuffer,
                                uint16_t& type,
                                uint16_t& ip_size,
                                uint16_t& ip_offset,
                                const uint16_t& eth_offset,
                                const struct ndpi_ethhdr * & ethernet);
	int setL2Ip(pcap_pkthdr const * const header,
                            uint8_t const * const packet,
                            uint16_t& type,
                            uint16_t& ip_size,
                            uint16_t& ip_offset,
                            const struct ndpi_iphdr * & ip,
                            struct ndpi_ipv6hdr * & ip6);
	int processL3(FlowInfo& flow,
                          pcap_pkthdr const * const header,
                          uint8_t const * const packet,
                          uint16_t& type,
                          uint16_t& ip_size,
                          uint16_t& ip_offset,
                          const struct ndpi_iphdr * & ip,
                          struct ndpi_ipv6hdr * & ip6,
                          const uint8_t * & l4_ptr,
                          uint16_t& l4_len);
	int processL4(FlowInfo& flow,
                          pcap_pkthdr const * const header,
                          uint8_t const * const packet,
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



struct ntpcap_ts_s {
    uint32_t sec;
    uint32_t usec;
};

struct ntpcap_hdr_s {
    struct ntpcap_ts_s ts;
    uint32_t caplen;
    uint32_t wirelen;
};

#endif
