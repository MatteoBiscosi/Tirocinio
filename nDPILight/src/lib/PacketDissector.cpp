#include ndpi_light_includes.h


PacketDissector::PacketDissector(uint num)
{
    this->captured_stats.protos_cnt = new uint16_t[num + 1] ();
}



PacketDissector::~PacketDissector()
{
    if(pkt_parser == nullptr)
	    return;
        
    if(pkt_parser->captured_stats.protos_cnt != nullptr)
        delete [] pkt_parser->captured_stats.protos_cnt;
}

