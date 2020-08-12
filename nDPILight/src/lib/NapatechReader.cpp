
#include "ndpi_light_includes.h"


/* ********************************** */

/*  Costructors and Destructors  */
NapatechReader::NapatechReader() : file_or_device(nullptr)
{
    file_or_device = nullptr;
}

NapatechReader::NapatechReader(const char *dst) : file_or_device(nullptr)
{
    file_or_device = dst;
}

/* ********************************** */

int NapatechReader::handleErrorStatus(int status, const char* message)
{
  if(this->status != NT_SUCCESS) {
    char errorBuffer[NT_ERRBUF_SIZE];
    NT_ExplainError(this->status, errorBuffer, sizeof(errorBuffer));
    tracer->traceEvent(0, "%s: %s\n", message, errorBuffer);
    return 1;
  }
}

/* ********************************** */

int NapatechReader::ntplCall(const char* str)
{
  NtNtplInfo_t ntplInfo;
  this->status = NT_NTPL(this->hCfgStream, str, &ntplInfo, NT_NTPL_PARSER_VALIDATE_NORMAL);
  return handleErrorStatus(this->status, "NT_NTPL() failed");
}

/* ********************************** */

void NapatechReader::DumpL4(NtDyn1Descr_t * & pDyn1)
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

void NapatechReader::DumpIPv4(NtDyn1Descr_t * & pDyn1)
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

void NapatechReader::DumpIPv6(NtDyn1Descr_t * & pDyn1)
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

int NapatechReader::setFilters() 
{
    // Deletion of filters and macros, and clear FPGA flow tables.
    if(this->ntplCall("Delete = All") != 0)
        return 1;

    // Set new filters and flow tables settings
    if(this->ntplCall("KeyType[Name=kt] = {sw_32_32,   sw_16_16}") != 0)
        return 1;
    if(this->ntplCall("KeyDef[Name=kd; KeyType=kt] = (Layer3Header[12]/32/32,  Layer4Header[0]/16/16)") != 0)
        return 1;
    if(this->ntplCall("Assign[StreamId=1; Descriptor=DYN1] = Key(kd, KeyID=1)==MISS") != 0)
        return 1;

    return 0;
}

/* ********************************** */

int NapatechReader::setFlow()
{
    // Initialize flow stream attributes and set adapter number attribute.
    NT_FlowOpenAttrInit(&(this->flowAttr));
    NT_FlowOpenAttrSetAdapterNo(&(this->flowAttr), this->adapterNo);

    // Opens a flow programming stream and returns a stream handle (flowStream).
    this->status = NT_FlowOpen_Attr(&(this->flowStream), "open_flow_stream_example", &(this->flowAttr));
    if(handleErrorStatus(this->status, "Error while opening the flow stream") != 0)
        return 1;

    return 0;
}

int NapatechReader::setStream()
{
    this->status = NT_NetRxOpen(&(this->hNetRx), "test stream", NT_NET_INTERFACE_PACKET, 1, -1);
    if(handleErrorStatus(this->status, "NT_NetRxOpen() failed") != 0)
        return 1;
    
    return 0;
}

/* ********************************** */

int NapatechReader::initFileOrDevice()
{
    // Initialize napatech
    this->status = NT_Init(NTAPI_VERSION);

    // Open a configuration stream to assign a filter to a stream ID.
    this->status = NT_ConfigOpen(&hCfgStream, "Learn_example_config");
    if(this->handleErrorStatus(status, "NT_ConfigOpen() failed") != 0)
        return 1;
    
    if(this->setFilters() != 0)
        return 1;

    if(this->setFlow() != 0)
        return 1;

    if(this->setStream() != 0)
        return 1;

    return 0;
}

/* ********************************** */

void NapatechReader::getDyn(NtNetBuf_t& hNetBuffer)
{
    // descriptor DYN1 is used, which is set up via NTPL.
    NtDyn1Descr_t* pDyn1 = NT_NET_DESCR_PTR_DYN1(hNetBuffer);
    uint8_t* packet = reinterpret_cast<uint8_t*>(pDyn1) + pDyn1->descrLength;

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

int NapatechReader::startRead()
{
    NtNetBuf_t hNetBuffer;

    while(this->error_or_eof == 0) {
        // Get package from rx stream.
        this->status = NT_NetRxGetNextPacket(hNetRx, &hNetBuffer, -1);
        
        if(this->status == NT_STATUS_TIMEOUT || status == NT_STATUS_TRYAGAIN) 
            continue;

        if(this->status == NT_ERROR_NT_TERMINATING)
	    break;

        if(handleErrorStatus(this->status, "Error while sniffing next packet") != 0) {
            this->error_or_eof = 1;
            return 1;
        }

        pktCounter++;

        tracer->traceEvent(2, "Packet received;\tPacket number: %3llu\n", this->pktCounter);
	
        this->getDyn(hNetBuffer);
    }	

    this->error_or_eof = 1;

    return 0;
}

/* ********************************** */

void NapatechReader::stopRead()
{
    this->error_or_eof = 1;
    sleep(5);    

    // Closes rx stream.
    NT_NetRxClose(hNetRx);    
}

/* ********************************** */

int NapatechReader::checkEnd()
{
    if(this->error_or_eof == 0)
        return 0;

    return -1;
}

/* ********************************** */
