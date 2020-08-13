#include "ndpi_light_includes.h"




/* ********************************** */

void NtDissector::DumpL4(NtDyn1Descr_t * & pDyn1)
{
    printf("    %3d %8s | ", pDyn1->ipProtocol, pDyn1->ipProtocol == 6 ? "TCP" : pDyn1->ipProtocol == 17 ? "UDP" : "Other");
    if (pDyn1->ipProtocol == 6) {
      struct TCPHeader_s *pl4 = (struct TCPHeader_s*)((uint8_t*)pDyn1 + pDyn1->descrLength + pDyn1->offset1);
      printf("    %04X |      %04X | ", ntohs(pl4->tcp_src), ntohs(pl4->tcp_dest));
      printf("      %03X | ", (pl4->reserved & 1) << 8 | pl4->tcp_ec_ctl);
    } else if (pDyn1->ipProtocol == 17) {
      struct UDPHeader_s *pl4 = (struct UDPHeader_s*)((uint8_t*)pDyn1 + pDyn1->descrLength + pDyn1->offset1);
      printf("    %04d |      %04d | ", ntohs(pl4->udp_src), ntohs(pl4->udp_dest));
      printf("%9s | ", "N/A");
    } else {
      printf("%8s %9s | ", " ", " ");
      printf("%9s | ", " ");
    }
    printf("%8d bytes\n", pDyn1->capLength - 4 - pDyn1->descrLength - pDyn1->offset0);
}

/* ********************************** */

void NtDissector::DumpIPv4(NtDyn1Descr_t * & pDyn1)
{
    uint32_t ipaddr;
    struct IPv4Header_s *pl3 = (struct IPv4Header_s*)((uint8_t*)pDyn1 + pDyn1->descrLength + pDyn1->offset0);
    printf("%-16s | %-15s - %-15s | %-16s | %-8s | %-9s | %-9s | %-8s\n", "Time", "Src", "Dest", "Protocol", "Src port", "Dest port", "TCP flags", "Bytes");
    printf("%16llu | ", pDyn1->timestamp);
    ipaddr = ntohl(pl3->ip_src);
    printf("%03d.%03d.%03d.%03d - ", (ipaddr >> 24) & 0xFF, (ipaddr >> 16) & 0xFF, (ipaddr >> 8) & 0xFF, ipaddr & 0xFF);
    ipaddr = ntohl(pl3->ip_dest);
    printf("%03d.%03d.%03d.%03d | ", (ipaddr >> 24) & 0xFF, (ipaddr >> 16) & 0xFF, (ipaddr >> 8) & 0xFF, ipaddr & 0xFF);
    DumpL4(pDyn1);
}

/* ********************************** */

void NtDissector::DumpIPv6(NtDyn1Descr_t * & pDyn1)
{
    int i;
    struct IPv6Header_s *pl3 = (struct IPv6Header_s*)((uint8_t*)pDyn1 + pDyn1->descrLength + pDyn1->offset0);
    printf("%-16s | %-32s - %-32s | %-16s | %-8s | %-9s | %-9s | %-8s\n", "Time", "Src", "Dest", "Protocol", "Src port", "Dest port", "TCP flags", "Bytes");
    printf("%16" PRIx64 " | ", pDyn1->timestamp);
    for(i=0; i < 16; i++) {
      printf("%02x", *(((uint8_t*)&pl3->ip_src)+i));
    }
    printf(" - ");
    for(i=0; i < 16; i++) {
      printf("%02x", *(((uint8_t*)&pl3->ip_dest)+i));
    }
    printf(" | ");
    DumpL4(pDyn1);
}

/* ********************************** */

void NtDissector::getDyn(NtNetBuf_t& hNetBuffer)
{
    // descriptor DYN1 is used, which is set up via NTPL.
    this->pDyn1 = NT_NET_DESCR_PTR_DYN1(hNetBuffer);
    this->packet = reinterpret_cast<uint8_t*>(pDyn1) + pDyn1->descrLength;

    if (pDyn1->color & (1 << 6)) {
        tracer->traceEvent(1, "Packet contain an error and decoding cannot be trusted\n");
    } else {
        if (pDyn1->color & (1 << 5)) {
            tracer->traceEvent(1, "A non IPv4,IPv6 packet received\n");
        } else {
            switch (pDyn1->color >> 2) {
            case 0:  // IPv4
                    DumpIPv4(pDyn1);
                    break;
            case 1:  // IPv6
                    DumpIPv6(pDyn1);
                    break;
            case 2:  // Tunneled IPv4
                    DumpIPv4(pDyn1);
                    break;
            case 3:  // Tunneled IPv6
                    DumpIPv6(pDyn1);
                    break;
            }
        }
    }
}

/* ********************************** */

void NtDissector::processPacket(void * args,
                                    void * header_tmp,
                                    void * packet)
{
    FlowInfo flow = FlowInfo();
    Reader * reader = (Reader *) args;
    
    NtNetBuf_t * hNetBuffer = ((NtNetBuf_t *) header_tmp);

    size_t hashed_index = 0;
    void * tree_result = nullptr;
    FlowInfo * flow_to_process = nullptr;

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

    this->captured_stats.packets_captured++;

    printf("prova 2\n");
    if(!this->captured_stats.nt_time_start)
    	this->captured_stats.nt_time_start = (uint64_t) NT_NET_GET_PKT_TIMESTAMP(* hNetBuffer);
    printf("prova 2\n");
    printf("Prova 1, time: %llu\n", this->captured_stats.nt_time_start);

    this->captured_stats.nt_time_end = (uint64_t) NT_NET_GET_PKT_TIMESTAMP(* hNetBuffer);
    
    reader->newPacket((void *)hNetBuffer);

    std::cout << "Prova 3\n";
    tracer->traceEvent(2, "Packet received;\tPacket number: %3llu\n", this->captured_stats.packets_captured);

    this->getDyn(* hNetBuffer);

    std::cout << "Prova 4\n";
    pkt_parser->captured_stats.packets_processed++;
    pkt_parser->captured_stats.total_l4_data_len += l4_len;

    /*
    if(this->searchVal(reader, flow, tree_result, ip6, hashed_index) != 0) {
        if(this->addVal(reader, flow, flow_to_process, hashed_index, ndpi_src, ndpi_dst) != 0) {
            this->captured_stats.discarded_bytes += header->len;
            return;
        }
        else
            this->captured_stats.total_flows_captured++;
    } else {
        flow_to_process = *(FlowInfo **)tree_result;

        if (ndpi_src != flow_to_process->ndpi_src) {
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
    /*if (flow_to_process->first_seen == 0) {
        flow_to_process->first_seen = time_ms;
    }
    flow_to_process->last_seen = time_ms;
    /* current packet is an TCP-ACK? */
    //flow_to_process->flow_ack_seen = flow.flow_ack_seen;

    /* TCP-FIN: indicates that at least one side wants to end the connection */
    /*if (flow.flow_fin_ack_seen != 0 && flow_to_process->flow_fin_ack_seen == 0) {
        flow_to_process->flow_fin_ack_seen = 1;
        tracer->traceEvent(4, "[%8llu, %4u] end of flow\n",
                                    this->captured_stats.packets_captured, flow_to_process->flow_id);
        this->captured_stats.discarded_bytes += header->len;
        return;
    }

    this->printFlowInfos(reader, flow_to_process, ip, ip6, ip_size, ndpi_src, ndpi_dst, time_ms);
*/}

/* ********************************** */
