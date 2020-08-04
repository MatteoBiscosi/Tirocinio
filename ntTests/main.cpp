#include <cstring>

#include <nt.h>



void handleErrorStatus(int status, const char* message)
{
  if(status != NT_SUCCESS) {
    char errorBuffer[NT_ERRBUF_SIZE];
    NT_ExplainError(status, errorBuffer, sizeof(errorBuffer));
    std::cerr << message << ": " << errorBuffer << std::endl;
    std::exit(EXIT_FAILURE);
  }
}




int main(int argc, char *argv[]) 
{
    uint8_t         adapterNo = 0;
    NtFlowAttr_t    flowAttr;
    NtFlowStream_t  flowStream;
    uint64_t idCounter = 0;
    uint32_t streamId = 1;

    NtNetStreamRx_t hNetRx;
    NtNetBuf_t hNetBuffer;

    uint64_t pktCounter = 0;


    KeyType[Name=kt] = {sw_32_32,   sw_16_16}
    KeyDef[Name=kd; KeyType=kt] = (Layer3Header[12]/32/32,  Layer4Header[0]/16/16)

    Assign[StreamId=1] = Key(kd, KeyID=1)==MISS


    // Initialize flow stream attributes and set adapter number attribute.
    NT_FlowOpenAttrInit(&flowAttr);
    NT_FlowOpenAttrSetAdapterNo(&flowAttr, adapterNo);

    // Opens a flow programming stream and returns a stream handle (flowStream).
    status = NT_FlowOpen_Attr(&flowStream, "open_flow_stream_example", &flowAttr);
    if(status != NT_SUCCESS) {
        handleErrorStatus(status, "Error while opening the flow stream");
        return;
    }

    status = NT_NetRxOpen(&hNetRx, "test stream", NT_NET_INTERFACE_PACKET, 1, -1);
    handleErrorStatus(status, "NT_NetRxOpen() failed");

    // While not included here, it is needed to open a stream with
    // StreamId=1 for hNetRx before the while loop.
    while(pkCounter < 1000) {
        // Get package from rx stream.
        status = NT_NetRxGetNextPacket(hNetRx, &hNetBuffer, 100);
        if(status == NT_STATUS_TIMEOUT || status == NT_STATUS_TRYAGAIN) continue;
        if(status != NT_SUCCESS) {
            handleErrorStatus(status, "Error while sniffing next packet");
            return;
        }

        pktCounter++;

        std::cout << "Packet received;\tPacket number: " << pktCounter << "\n";

        // For this example the descriptor DYN3 is used, which is set up via NTPL.
        NtDyn4Descr_t* dyn4 = _NT_NET_GET_PKT_DESCR_PTR_DYN4(hNetBuffer);
        uint8_t* packet = reinterpret_cast<uint8_t*>(dyn4) + dyn4->descrLength;

        // In this example, the ID is a simple incremental value;
        // however, any value can be used, including the raw value of pointers.
        NtFlow_t flow;
        std::memset(&flow, 0x0, sizeof(NtFlow_t));
        flow.id = idCounter++;    // User defined ID
        flow.color = 0;           // Flow color
        flow.ipProtocolField = 6; // IP protocol number of next header (6: TCP)
        flow.keyId = 1;           // Key ID as used in the NTPL Key Test
        flow.keySetId = 4;        // Ket Set ID as used in the NTPL filter
        flow.op = 1;              // Flow programming operation
        flow.gfi = 1;             // Generate flow info record
        flow.tau = 1;             // TCP auto unlearn

        // The NTPL filters in this snippet set up an alternative offset0,
        // such that it points directly to the IP source address.
        std::memcpy(flow.keyData,      packet + dyn4->offset0,     4); // IPv4 src
        std::memcpy(flow.keyData + 4,  packet + dyn4->offset0 + 4, 4); // IPv4 dst
        std::memcpy(flow.keyData + 8,  packet + dyn4->offset1,     2); // TCP port src
        std::memcpy(flow.keyData + 10, packet + dyn4->offset1 + 2, 2); // TCP port dst

        // Program the flow into the adapter.
        status = NT_FlowWrite(flowStream, &flow, -1);
        if(status != NT_SUCCESS) {
            handleErrorStatus(status, "Error while adding the new flow");
            return;
        }
    }

    // Closes rx stream.
    status = NT_NetRxClose(hNetRx);
    handleErrorStatus(status, "NT_NetRxClose() failed");

    // Closes flow programming stream
    status = NT_FlowClose(flowStream);
    handleErrorStatus(status, "NT_FlowClose() failed");
}