
#include <cstring>
#include <iostream>
#include <cstdio>
#include <arpa/inet.h>
#include <inttypes.h>

#include <nt.h>

struct IPv6Header_s {
  // Little endian encoding
        uint8_t ip_tclass1:4;
        uint8_t ip_v:4;
        uint8_t ip_flow1:4;
        uint8_t ip_tclass2:4;
        uint16_t ip_flow2;
        uint16_t ip_len;
        uint8_t ip_nexthdr;
        uint8_t ip_hoplim;
	uint32_t ip_src[4];
	uint32_t ip_dest[4];
}; // 40 bytes;


struct IPv4Header_s {
  uint16_t ip_hl: 4;
  uint16_t ip_v: 4;
  uint16_t ip_tos: 8;
  uint16_t ip_len;
  uint32_t ip_id:16;
  uint32_t ip_frag_off:16;
#define IP_DONT_FRAGMENT  0x4000
#define IP_MORE_FRAGMENTS 0x2000
  uint32_t ip_ttl:8;
  uint32_t ip_prot:8;
  uint32_t ip_crc:16;
  uint32_t ip_src;
  uint32_t ip_dest;
}; //20 bytes
struct UDPHeader_s {
  uint32_t udp_src:16;
  uint32_t udp_dest:16;
  uint32_t udp_len:16;
  uint32_t udp_crc:16;
}; // 8 bytes
struct TCPHeader_s {
  uint32_t tcp_src:16;
  uint32_t tcp_dest:16;
  uint32_t tcp_seq;
  uint32_t tcp_ack;
  uint32_t reserved:4;
  uint32_t tcp_doff:4;
  uint32_t tcp_ec_ctl:8;
  uint32_t tcp_window:16;
  uint32_t tcp_crc:16;
  uint32_t tcp_urgp:16;
}; // 20 bytes



void handleErrorStatus(int status, const char* message)
{
  if(status != NT_SUCCESS) {
    char errorBuffer[NT_ERRBUF_SIZE];
    NT_ExplainError(status, errorBuffer, sizeof(errorBuffer));
    std::cerr << message << ": " << errorBuffer << std::endl;
    std::exit(EXIT_FAILURE);
  }
}


void ntplCall(NtConfigStream_t& hCfgStream, const char* str)
{
  std::cout << str << std::endl;

  NtNtplInfo_t ntplInfo;
  int status = NT_NTPL(hCfgStream, str, &ntplInfo, NT_NTPL_PARSER_VALIDATE_NORMAL);
  handleErrorStatus(status, "NT_NTPL() failed");
}


static void DumpL4(NtDyn1Descr_t *pDyn1)
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
static void DumpIPv4(NtDyn1Descr_t *pDyn1)
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
static void DumpIPv6(NtDyn1Descr_t *pDyn1)
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



int main(int argc, char *argv[]) 
{
    uint8_t         adapterNo = 0;
    NtFlowAttr_t    flowAttr;
    NtFlowStream_t  flowStream;
    uint64_t idCounter = 0;
    uint32_t streamId = 1;
   

    NtConfigStream_t hCfgStream;
    NtNetStreamRx_t hNetRx;
    NtNetBuf_t hNetBuffer;

    uint64_t pktCounter = 0;

   int status = NT_Init(NTAPI_VERSION);
   // Open a configuration stream to assign a filter to a stream ID.
   
   status = NT_ConfigOpen(&hCfgStream, "Learn_example_config");
   handleErrorStatus(status, "NT_ConfigOpen() failed");
   //
   //       // Deletion of filters and macros, and clear FPGA flow tables.
   ntplCall(hCfgStream, "Delete = All");
   //

   ntplCall(hCfgStream, "KeyType[Name=kt] = {sw_32_32,   sw_16_16}");
   ntplCall(hCfgStream, "KeyDef[Name=kd; KeyType=kt] = (Layer3Header[12]/32/32,  Layer4Header[0]/16/16)");

   
   ntplCall(hCfgStream, "Assign[StreamId=1; Descriptor=DYN1] = Key(kd, KeyID=1)==MISS");


    // Initialize flow stream attributes and set adapter number attribute.
    NT_FlowOpenAttrInit(&flowAttr);
    NT_FlowOpenAttrSetAdapterNo(&flowAttr, adapterNo);

    // Opens a flow programming stream and returns a stream handle (flowStream).
    status = NT_FlowOpen_Attr(&flowStream, "open_flow_stream_example", &flowAttr);
    if(status != NT_SUCCESS) {
        handleErrorStatus(status, "Error while opening the flow stream");
        return 0;
    }

    status = NT_NetRxOpen(&hNetRx, "test stream", NT_NET_INTERFACE_PACKET, 1, -1);
    handleErrorStatus(status, "NT_NetRxOpen() failed");

    // hile not included here, it is needed to open a stream with
    // StreamId=1 for hNetRx before the while loop.

    while(true) {
        // Get package from rx stream.
        status = NT_NetRxGetNextPacket(hNetRx, &hNetBuffer, 100);
        if(status == NT_STATUS_TIMEOUT || status == NT_STATUS_TRYAGAIN) continue;
        if(status != NT_SUCCESS) {
            handleErrorStatus(status, "Error while sniffing next packet");
            return 0;
        }

        pktCounter++;

        std::cout << "Packet received;\tPacket number: " << pktCounter << "\n";
	
        // For this example the descriptor DYN3 is used, which is set up via NTPL.
        NtDyn1Descr_t* pDyn1 = NT_NET_DESCR_PTR_DYN1(hNetBuffer);
        uint8_t* packet = reinterpret_cast<uint8_t*>(pDyn1) + pDyn1->descrLength;

	if (pDyn1->color & (1 << 6)) {
      		printf("Packet contain an error and decoding cannot be trusted\n");
    	} else {
      	if (pDyn1->color & (1 << 5)) {
        	printf("A non IPv4,IPv6 packet received\n");
      	} else if (pDyn1->color & 3) {
          	printf("Fragmented packet. Must be assembled before the netflow information can be gathered\n");
      		} else {
        		switch (pDyn1->color >> 2) {
          		case 0:  // IPv4
            			printf("IPv4 packet received\n");
            			DumpIPv4(pDyn1);
            			break;
          		case 1:  // IPv6
            			printf("IPv6 packet received\n");
            			DumpIPv6(pDyn1);
            			break;
          		case 2:  // Tunneled IPv4
            			printf("Tunneled IPv4 packet received\n");
            			DumpIPv4(pDyn1);
           	 		break;
          		case 3:  // Tunneled IPv6
            			printf("Tunneled IPv6 packet received\n");
            			DumpIPv6(pDyn1);
            			break;
        		}
        	}
    	}
    }	

    // Closes rx stream.
    status = NT_NetRxClose(hNetRx);
    handleErrorStatus(status, "NT_NetRxClose() failed");

    // Closes flow programming stream
    status = NT_FlowClose(flowStream);
    handleErrorStatus(status, "NT_FlowClose() failed");

    return 0;
}
