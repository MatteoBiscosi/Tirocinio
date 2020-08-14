
#include <cstring>
#include <iostream>
#include <cstdio>






void handleErrorStatus(int status, const char* message)
{
  if(status != NT_SUCCESS) {
    char errorBuffer[NT_ERRBUF_SIZE];
    NT_ExplainError(status, errorBuffer, sizeof(errorBuffer));
    std::cerr << message << ": " << errorBuffer << std::endl;
    std::exit(EXIT_FAILURE);
  }
}

/* ********************************** */

void ntplCall(NtConfigStream_t& hCfgStream, const char* str)
{
  std::cout << str << std::endl;

  NtNtplInfo_t ntplInfo;
  int status = NT_NTPL(hCfgStream, str, &ntplInfo, NT_NTPL_PARSER_VALIDATE_NORMAL);
  handleErrorStatus(status, "NT_NTPL() failed");
}




int main(int argc, char *argv[]) 
{
    int status;
    uint64_t idCounter = 0U;
    std::vector<std::unique_ptr<NtFlow_t>> learnedFlowList;

    NtFlowAttr_t    flowAttr;
    NtFlowStream_t  flowStream;

    NtNetStreamRx_t hNetRx;
    NtNetBuf_t      hNetBuffer;


    if(ntplCall("Delete = All") != 0)
        return 1;

    // Set new filters and flow tables settings
    if(ntplCall("KeyType[Name=kt] = {sw_32_32,   sw_16_16}") != 0)
        return 1;
    if(ntplCall("KeyDef[Name=kd; KeyType=kt] = (Layer3Header[12]/32/32,  Layer4Header[0]/16/16)") != 0)
        return 1;
    if(ntplCall("Assign[StreamId=1; Descriptor=DYN1] = Key(kd, KeyID=1)==MISS") != 0)
        return 1;

    // Initialize flow stream attributes and set adapter number attribute.
    NT_FlowOpenAttrInit(&(flowAttr));
    NT_FlowOpenAttrSetAdapterNo(&(flowAttr), 0);

    // Opens a flow programming stream and returns a stream handle (flowStream).
    status = NT_FlowOpen_Attr(&(flowStream), "open_flow_stream_example", &(flowAttr));
    if(handleErrorStatus(status, "Error while opening the flow stream") != 0)
        return 1;

    status = NT_NetRxOpen(&(hNetRx), "test stream", NT_NET_INTERFACE_PACKET, 1, -1);
    if(handleErrorStatus(status, "NT_NetRxOpen() failed") != 0)
        return 1;

    while(error_or_eof == 0) {
        // Get package from rx stream.
        status = NT_NetRxGetNextPacket(hNetRx, &(hNetBuffer), -1);
        
        if(status == NT_STATUS_TIMEOUT || status == NT_STATUS_TRYAGAIN) 
            continue;

        if(status == NT_ERROR_NT_TERMINATING)
	    break;

        if(handleErrorStatus(status, "Error while sniffing next packet") != 0) {
            error_or_eof = 1;
            return 1;
        }
        std::cout << "New flow\n";
        // Here a package has successfully been received, and the parameters for the
        // next flow to be learned will be set up.
        auto flow = std::unique_ptr<NtFlow_t>(new NtFlow_t);
        std::memset(flow.get(), 0x0, sizeof(NtFlow_t));

        // In this example, the ID is a simple incremental value that can be used
        // for lookup in the std::vector learnedFlowList. However, any value can be used,
        // including the raw value of pointers.
        flow->id              = idCounter++;  // User defined ID
        flow->color           = 0;            // Flow color
        flow->overwrite       = 0;            // Overwrite filter action (1: enable, 0: disable)
        flow->streamId        = 0;            // Marks the stream id if overwrite filter action is enabled
        flow->ipProtocolField = 6;            // IP protocol number of next header (6: TCP)
        flow->keySetId        = KEY_SET_ID;   // Key Set ID as used in the NTPL filter
        flow->op              = 1;            // Flow programming operation (1: learn, 0: un-learn)
        flow->gfi             = 1;            // Generate flow info record (1: generate, 0: do not generate)
        flow->tau             = 0;            // TCP auto unlearn (1: auto unlearn enable, 0: auto unlearn disable)

        // For this example the descriptor DYN3 is used, which is set up by NTPL.
        NtDyn4Descr_t* dyn4 = _NT_NET_GET_PKT_DESCR_PTR_DYN4(hNetBuffer);
        uint8_t* packet = reinterpret_cast<uint8_t*>(dyn4) + dyn4->descrLength;

        // Because colormask was used in the filters, it is very easy to check for
        // the IP type.
        // The filters also set up an alternative offset0, such that it points
        // directly to the IP source address.
        switch(dyn4->color0 & (COLOR_IPV4 | COLOR_IPV6)) {
            case COLOR_IPV4: {
                *ipv4counter += 1U;
                std::memcpy(flow->keyData,      packet + dyn4->offset0,     4);  // IPv4 src
                std::memcpy(flow->keyData + 4,  packet + dyn4->offset0 + 4, 4);  // IPv4 dst
                std::memcpy(flow->keyData + 8,  packet + dyn4->offset1,     2);  // TCP port src
                std::memcpy(flow->keyData + 10, packet + dyn4->offset1 + 2, 2);  // TCP port dst
                flow->keyId = KEY_ID_IPV4;  // Key ID as used in the NTPL Key Test
                break;
            }
            case COLOR_IPV6: {
                *ipv6counter += 1U;
                std::memcpy(flow->keyData,      packet + dyn4->offset0,      16);  // IPv6 src
                std::memcpy(flow->keyData + 16, packet + dyn4->offset0 + 16, 16);  // IPv6 dst
                std::memcpy(flow->keyData + 32, packet + dyn4->offset1,      2);   // TCP port src
                std::memcpy(flow->keyData + 34, packet + dyn4->offset1 + 2,  2);   // TCP port dst
                flow->keyId = KEY_ID_IPV6;  // Key ID as used in the NTPL Key Test
                break;
            }	
        }

        // Program the flow into the adapter.
        status = NT_FlowWrite(flowStream, flow.get(), -1);
        handleErrorStatus(status, "NT_FlowWrite() failed");

        learnedFlowList.push_back(std::move(flow));
    }

    error_or_eof = 1;

    return 0;
}
