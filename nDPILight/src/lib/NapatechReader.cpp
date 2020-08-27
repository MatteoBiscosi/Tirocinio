
#include "ndpi_light_includes.h"


/* ********************************** */

int handleErrorStatus(int status, const char* message)
/**
 * Function used to handle nt errors
 */
{
  if(status != NT_SUCCESS) {
    char errorBuffer[NT_ERRBUF_SIZE];
    NT_ExplainError(status, errorBuffer, sizeof(errorBuffer));
    tracer->traceEvent(0, "%s: %s\n", message, errorBuffer);
    return 1;
  }

  return 0;
}

/* ********************************** */

int ntplCall(NtConfigStream_t& hCfgStream, const char* str)
/**
 * Function used to add new features to the 
 * configuration stream
 */
{
    NtNtplInfo_t ntplInfo;
    int status = NT_NTPL(hCfgStream, str, &ntplInfo, NT_NTPL_PARSER_VALIDATE_NORMAL);
    if(handleErrorStatus(status, "NT_NTPL() failed") != 0)
        return 1;

    return 0;
}

/* ********************************** */

void nt_idle_scan_walker(void const * const A, ndpi_VISIT which, int depth, void * const user_data)
/**
 * Function used to check for idle flows instead of
 * ndpi_idle_scan_walker
 */
{   
    NapatechReader * const workflow = (NapatechReader *)user_data;
    FlowInfo * const flow = *(FlowInfo **)A;

    (void)depth;

    if (workflow == nullptr || flow == nullptr) {
        return;
    }

    if (which == ndpi_preorder || which == ndpi_leaf) {
        if ((flow->flow_fin_ack_seen == 1 && flow->flow_ack_seen == 1) ||
            flow->last_seen + MAX_IDLE_TIME * 1000  < workflow->getLastTime())
            /*  New flow that need to be added to idle flows    */
        {
            char src_addr_str[INET6_ADDRSTRLEN+1];
            char dst_addr_str[INET6_ADDRSTRLEN+1];
            flow->ipTupleToString(src_addr_str, sizeof(src_addr_str), dst_addr_str, sizeof(dst_addr_str));
            workflow->incrCurIdleFlows();
            workflow->getNdpiFlowsIdle()[workflow->getCurIdleFlows()] = flow;
            workflow->incrTotalIdleFlows();
        }
    }
}

/* ********************************** */

void taskReceiverUnh(const char* streamName, NapatechReader *reader)
/**
 * Function used to handle the unhandled stream
 */
{
    int status;

    while(reader->getErrorOfEof() == 0) {
        // Get package from rx stream.
        status = NT_NetRxGetNextPacket(* reader->getUnhStream(), reader->getUnhBuffer(), -1);
        
        if(status == NT_STATUS_TIMEOUT || status == NT_STATUS_TRYAGAIN) 
            continue;

        if(status == NT_ERROR_NT_TERMINATING)
	        break;

        if(handleErrorStatus(status, "Error while sniffing next packet") != 0) {
            continue;
        }

        pkt_parser->incrUnhaPkts();

        NT_NetRxRelease(* reader->getUnhStream(), * reader->getUnhBuffer());
    }	
}

/* ********************************** */

NapatechReader::~NapatechReader()
{
    this->error_or_eof = 1;

    // Closes the configuration
    NT_ConfigClose(hCfgStream);

    // Closes rx stream.
    NT_NetRxClose(hNetRxAny);
    NT_NetRxClose(hNetRxUnh); 
}  

/* ********************************** */

int NapatechReader::initModule()
{
    ndpi_init_prefs init_prefs = ndpi_no_prefs;
    this->ndpi_struct = ndpi_init_detection_module(init_prefs);
    if (this->ndpi_struct == nullptr) {
        return -1;
    }

    return 0;
}

/* ********************************** */

int NapatechReader::initInfos()
{
    /* Actual time */
    struct timeval actual_time;
    gettimeofday(&actual_time, nullptr);
    this->last_idle_scan_time = (uint64_t) actual_time.tv_sec * TICK_RESOLUTION + actual_time.tv_usec / (1000000 / TICK_RESOLUTION);

    this->total_active_flows = 0; /* First initialize active flow's infos */
    this->max_active_flows = MAX_FLOW_ROOTS_PER_THREAD;
    this->max_idle_scan_index = MAX_FLOW_ROOTS_PER_THREAD / 8;
    this->ndpi_flows_active = (void **)ndpi_calloc(this->max_active_flows, sizeof(void *));
    if (this->ndpi_flows_active == nullptr) {
        return -1;
    }

    this->total_idle_flows = 0; /* Then initialize idle flow's infos */
    this->max_idle_flows = MAX_IDLE_FLOWS_PER_THREAD;
    this->ndpi_flows_idle = (void **)ndpi_calloc(this->max_idle_flows, sizeof(void *));
    if (this->ndpi_flows_idle == nullptr) {
        return -1;
    }

    NDPI_PROTOCOL_BITMASK protos; /* In the end initialize bitmask's infos */
    NDPI_BITMASK_SET_ALL(protos);
    ndpi_set_protocol_detection_bitmask2(this->ndpi_struct, &protos);
    ndpi_finalize_initalization(this->ndpi_struct);

    pkt_parser->initProtosCnt(ndpi_get_num_supported_protocols(this->ndpi_struct));

    return 0;
}

/* ********************************** */

int NapatechReader::initFileOrDevice()
{
    if(this->initModule() != 0) {
        tracer->traceEvent(0, "Error initializing detection module\n");
        delete(this);
        return -1;
    }

    if(this->initInfos() != 0) {
        tracer->traceEvent(0, "Error initializing structure infos\n");
        delete(this);
        return -1;
    }
	
    return 0;
}

/* ********************************** */

void NapatechReader::newPacket(void * header) 
{    
    NtNetBuf_t * hNetBuffer = (NtNetBuf_t *) header;   

    this->last_time = (uint64_t) NT_NET_GET_PKT_TIMESTAMP(* hNetBuffer);

    /*  Scan done every 15000 ms more or less   */    
    pkt_parser->incrWireBytes(NT_NET_GET_PKT_CAP_LENGTH(* hNetBuffer) - NT_NET_GET_PKT_DESCR_LENGTH(* hNetBuffer));
    this->checkForIdleFlows();
}

/* ********************************** */

void NapatechReader::checkForIdleFlows()
{
	/*  Check if at least IDLE_SCAN_PERIOD passed since last scan   */
	if (this->last_idle_scan_time + IDLE_SCAN_PERIOD * 10000 < this->last_time) { 
		for (this->idle_scan_index; this->idle_scan_index < this->max_idle_scan_index; ++this->idle_scan_index) {
			if(this->ndpi_flows_active[this->idle_scan_index] == nullptr)
				continue;

			ndpi_twalk(this->ndpi_flows_active[this->idle_scan_index], nt_idle_scan_walker, this);

			/*  Removes all idle flows that were copied into ndpi_flows_idle from the ndpi_twalk    */
			while (this->cur_idle_flows > 0) {
				/*  Get the flow    */
				FlowInfo * const tmp_f =
					(FlowInfo *)this->ndpi_flows_idle[--this->cur_idle_flows];

				if(tmp_f == nullptr)
					continue;

				if (tmp_f->flow_fin_ack_seen == 1) {
					tracer->traceEvent(4, "[%4u] Freeing flow due to fin\n", tmp_f->flow_id);
				} else {
					tracer->traceEvent(4, "[%4u] Freeing idle flow\n", tmp_f->flow_id);
				}
				
                		pkt_parser->printFlow(this, tmp_f);

				/*  Removes it from the active flows    */
				ndpi_tdelete(tmp_f, &this->ndpi_flows_active[this->idle_scan_index],
						ndpi_workflow_node_cmp);

				if(tmp_f != nullptr)
					flowFreer(tmp_f);

				this->cur_active_flows--;
			}
		}

		this->last_idle_scan_time = this->last_time;
		this->last_packets_scan = pkt_parser->getPktsCaptured();

		/* Updating next max_idle_scan_index */
		this->max_idle_scan_index = ((this->idle_scan_index + this->max_idle_scan_index) % this->max_active_flows) + 1;
	}
}

/* ********************************** */

void NapatechReader::taskReceiverAny(const char* streamName, NtFlowStream_t& flowStream)
{
    uint64_t counter = 0;
    int status;
    uint64_t idCounter = 0U;
    std::vector<std::unique_ptr<NtFlow_t>> learnedFlowList;   
    
    
    int status = NT_NetRxOpen(&(this->hNetRxMiss), "Miss packets stream", NT_NET_INTERFACE_PACKET, STREAM_ID_MISS, -1);
    if(handleErrorStatus(status, "NT_NetRxOpen() failed") != 0)
        return 1;


    while(this->error_or_eof == 0) {
        // Get package from rx stream.
        status = NT_NetRxGet(this->hNetRxMiss, &(this->hNetBufferMiss), -1);
	        
        if(status == NT_STATUS_TIMEOUT || status == NT_STATUS_TRYAGAIN) 
            continue;

        if(status == NT_ERROR_NT_TERMINATING)
	    break;

        if(handleErrorStatus(status, "Error while sniffing next packet") != 0)
            continue;
	
        pkt_parser->processPacket(this, &(this->hNetBufferMiss), nullptr);
	
        if(this->newFlowCheck == true) {
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
            flow->ipProtocolField = 17;            // IP protocol number of next header (6: TCP)
            flow->keySetId        = KEY_SET_ID;   // Key Set ID as used in the NTPL filter
            flow->op              = 1;            // Flow programming operation (1: learn, 0: un-learn)
            flow->gfi             = 1;            // Generate flow info record (1: generate, 0: do not generate)
            flow->tau             = 0;            // TCP auto unlearn (1: auto unlearn enable, 0: auto unlearn disable)

            // For this example the descriptor DYN3 is used, which is set up by NTPL.
            //        NtDyn1Descr_t* dyn4 = _NT_NET_GET_PKT_DESCR_PTR_DYN1(hNetBuffer);
            //      uint8_t* packet = reinterpret_cast<uint8_t*>(dyn4) + dyn4->descrLength;

            // Because colormask was used in the filters, it is very easy to check for
            // the IP type.
            // The filters also set up an alternative offset0, such that it points
            // directly to the IP source address.
            NtDyn1Descr_t* pDyn1 = _NT_NET_GET_PKT_DESCR_PTR_DYN1(this->hNetBufferMiss);
            uint8_t* packet = reinterpret_cast<uint8_t*>(pDyn1) + pDyn1->descrLength;

            switch (pDyn1->color >> 2) {
                case 0:  // IPv4
                        std::memcpy(flow->keyData,      packet + pDyn1->offset0,     4);  // IPv4 src
                        std::memcpy(flow->keyData + 4,  packet + pDyn1->offset0 + 4, 4);  // IPv4 dst
                        std::memcpy(flow->keyData + 8,  packet + pDyn1->offset1,     2);  // TCP port src
                        std::memcpy(flow->keyData + 10, packet + pDyn1->offset1 + 2, 2);  // TCP port dst
                        flow->keyId = KEY_ID_IPV4;  // Key ID as used in the NTPL Key Test
                        break;
                case 1:  // IPv6
                        std::memcpy(flow->keyData,      packet + pDyn1->offset0,      16);  // IPv6 src
                        std::memcpy(flow->keyData + 16, packet + pDyn1->offset0 + 16, 16);  // IPv6 dst
                        std::memcpy(flow->keyData + 32, packet + pDyn1->offset1,      2);   // TCP port src
                        std::memcpy(flow->keyData + 34, packet + pDyn1->offset1 + 2,  2);   // TCP port dst
                        flow->keyId = KEY_ID_IPV6;  // Key ID as used in the NTPL Key Test
                        break;
                case 2:  // Tunneled IPv4
                        std::memcpy(flow->keyData,      packet + pDyn1->offset0,     4);  // IPv4 src
                        std::memcpy(flow->keyData + 4,  packet + pDyn1->offset0 + 4, 4);  // IPv4 dst
                        std::memcpy(flow->keyData + 8,  packet + pDyn1->offset1,     2);  // TCP port src
                        std::memcpy(flow->keyData + 10, packet + pDyn1->offset1 + 2, 2);  // TCP port dst
                        flow->keyId = KEY_ID_IPV4;  // Key ID as used in the NTPL Key Test
                        break;
                case 3:  // Tunneled IPv6
                        std::memcpy(flow->keyData,      packet + pDyn1->offset0,      16);  // IPv6 src
                        std::memcpy(flow->keyData + 16, packet + pDyn1->offset0 + 16, 16);  // IPv6 dst
                        std::memcpy(flow->keyData + 32, packet + pDyn1->offset1,      2);   // TCP port src
                        std::memcpy(flow->keyData + 34, packet + pDyn1->offset1 + 2,  2);   // TCP port dst
                        flow->keyId = KEY_ID_IPV6;  // Key ID as used in the NTPL Key Test
                        break;
            }
            // Program the flow into the adapter.
            status = NT_FlowWrite(flowStream, flow.get(), -1);
            handleErrorStatus(status, "NT_FlowWrite() failed");

            learnedFlowList.push_back(std::move(flow));
        }
	
        status = NT_NetRxRelease(this->hNetRxMiss, this->hNetBufferMiss);
        if(handleErrorStatus(status, "Error while releasing packet") != 0)
            continue;
     }     
}

/* ********************************** */

int NapatechReader::startRead()
{
    NtFlowAttr_t    flowAttr;
    NtFlowStream_t  flowStream;
    NtConfigStream_t hCfgStream;

    int status;
    unsigned long long int idCounter = 0;

    status = NT_Init(NTAPI_VERSION);
    if(handleErrorStatus(status, "NT_NetRxOpen() failed") != 0) {
        delete(this);
        return 1;
    }
    
    // Open a configuration stream to assign a filter to a stream ID.
    status = NT_ConfigOpen(&hCfgStream, "Learn_example_config");

    ntplCall(hCfgStream, "Delete = All");
        

    // Set new filters and flow tables settings
    ntplCall(hCfgStream, "KeyType[Name=kt4] = {sw_32_32,   sw_16_16}");
	ntplCall(hCfgStream, "KeyType[Name=kt6] = {sw_128_128, sw_16_16}");
    ntplCall(hCfgStream, "KeyDef[Name=kd4; KeyType=kt4; IpProtocolField=Outer] = (Layer3Header[12]/32/32,  Layer4Header[0]/16/16)");
    ntplCall(hCfgStream, "keydef[Name=kd6; KeyType=kt6; IpProtocolField=Outer] = (Layer3Header[8]/128/128, Layer4Header[0]/16/16)");
   
    
	// Shorthand for the checks used in these filters.
    ntplCall(hCfgStream, "DefineMacro(\"LearnFilterCheck\", \"Port==$1 and Layer2Protocol==EtherII and Layer3Protocol==$2\")");
	//
	ntplCall(hCfgStream, "Assign[StreamId=" STR(STREAM_ID_MISS) "; Descriptor=DYN1, ColorBits=FlowID, Offset0=Layer3Header[12]; ColorMask=" STR(COLOR_IPV4) "] = LearnFilterCheck(0,ipv4) and Key(kd4, KeyID=" STR(KEY_ID_IPV4) ")==MISS");
    ntplCall(hCfgStream, "Assign[StreamId=" STR(STREAM_ID_MISS) "; Descriptor=DYN1, ColorBits=FlowID, Offset0=Layer3Header[8];  ColorMask=" STR(COLOR_IPV6) "] = LearnFilterCheck(0,ipv6) and Key(kd6, KeyID=" STR(KEY_ID_IPV6) ")==MISS");
    ntplCall(hCfgStream, "Assign[StreamId=" STR(STREAM_ID_MISS) "; Descriptor=DYN1, ColorBits=FlowID, Offset0=Layer3Header[12]; ColorMask=" STR(COLOR_IPV4) "] = LearnFilterCheck(1,ipv4) and Key(kd4, KeyID=" STR(KEY_ID_IPV4) ", FieldAction=Swap)==MISS");
    ntplCall(hCfgStream, "Assign[StreamId=" STR(STREAM_ID_MISS) "; Descriptor=DYN1, ColorBits=FlowID, Offset0=Layer3Header[8];  ColorMask=" STR(COLOR_IPV6) "] = LearnFilterCheck(1,ipv6) and Key(kd6, KeyID=" STR(KEY_ID_IPV6) ", FieldAction=Swap)==MISS");

    ntplCall(hCfgStream, "Assign[StreamId=" STR(STREAM_ID_UNHA) "] = LearnFilterCheck(0,ipv4) and Key(kd4, KeyID=" STR(KEY_ID_IPV4) ")==UNHANDLED");
    ntplCall(hCfgStream, "Assign[StreamId=" STR(STREAM_ID_UNHA) "] = LearnFilterCheck(0,ipv6) and Key(kd6, KeyID=" STR(KEY_ID_IPV6) ")==UNHANDLED");
    ntplCall(hCfgStream, "Assign[StreamId=" STR(STREAM_ID_UNHA) "] = LearnFilterCheck(1,ipv4) and Key(kd4, KeyID=" STR(KEY_ID_IPV4) ", FieldAction=Swap)==UNHANDLED");
    ntplCall(hCfgStream, "Assign[StreamId=" STR(STREAM_ID_UNHA) "] = LearnFilterCheck(1,ipv6) and Key(kd6, KeyID=" STR(KEY_ID_IPV6) ", FieldAction=Swap)==UNHANDLED");
    ntplCall(hCfgStream, "Assign[StreamId=Drop] = LearnFilterCheck(0,ipv4) and Key(kd4, KeyID=" STR(KEY_ID_IPV4) ", CounterSet=CSA)==" STR(KEY_SET_ID));
    ntplCall(hCfgStream, "Assign[StreamId=Drop] = LearnFilterCheck(0,ipv6) and Key(kd6, KeyID=" STR(KEY_ID_IPV6) ", CounterSet=CSA)==" STR(KEY_SET_ID));
    ntplCall(hCfgStream, "Assign[StreamId=Drop] = LearnFilterCheck(1,ipv4) and Key(kd4, KeyID=" STR(KEY_ID_IPV4) ", CounterSet=CSB, FieldAction=Swap)==" STR(KEY_SET_ID));
    ntplCall(hCfgStream, "Assign[StreamId=Drop] = LearnFilterCheck(1,ipv6) and Key(kd6, KeyID=" STR(KEY_ID_IPV6) ", CounterSet=CSB, FieldAction=Swap)==" STR(KEY_SET_ID));

    // Initialize flow stream attributes and set adapter number attribute.
    NT_FlowOpenAttrInit(&(flowAttr));
    NT_FlowOpenAttrSetAdapterNo(&(flowAttr), 0);

    // Opens a flow programming stream and returns a stream handle (flowStream).
    status = NT_FlowOpen_Attr(&(flowStream), "open_flow_stream_example", &(flowAttr));
    handleErrorStatus(status, "Error while opening the flow stream");
    if(handleErrorStatus(status, "Error while opening the flow stream") != 0)
        return -1;

    status = NT_NetRxOpen(&(this->hNetRxAny), "Miss packets stream", NT_NET_INTERFACE_PACKET, STREAM_ID_MISS, -1);
    if(handleErrorStatus(status, "NT_NetRxOpen() failed") != 0)
        return -1;

    status = NT_NetRxOpen(&(this->hNetRxUnh), "Unhandled packets stream", NT_NET_INTERFACE_PACKET, STREAM_ID_UNHA, -1);
    if(handleErrorStatus(status, "NT_NetRxOpen() failed") != 0)
        return -1;


    /* Analysis starts */
    tracer->traceEvent(2, "\tAnalysis started\r\n\r\n");

    std::thread receiverThread2(taskReceiverUnh, "flowmatch_example_receiver_net_rx_unhandled", this);
    this->taskReceiverAny("flowmatch_example_receiver_net_rx_miss", flowStream);

    receiverThread2.join();

    return 0;
}

/* ********************************** */

void NapatechReader::stopRead()
{
    this->error_or_eof = 1;
    sleep(5);    

    // Closes rx stream.
    NT_NetRxClose(hNetRxAny);
    NT_NetRxClose(hNetRxUnh);    
}

/* ********************************** */

int NapatechReader::checkEnd()
{
    if(this->error_or_eof == 0)
        return 0;

    return -1;
}

/* ********************************** */

void NapatechReader::printStats()
{
    pkt_parser->printStats((Reader *) this);
}

/* ********************************** */

