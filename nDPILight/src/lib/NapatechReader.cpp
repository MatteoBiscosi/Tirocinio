
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

int NapatechReader::setFilters() 
{
    // Deletion of filters and macros, and clear FPGA flow tables.
    if(this->ntplCall("Delete = All") != 0)
        return 1;

    // Set new filters and flow tables settings
    if(this->ntplCall("KeyType[Name=kt4] = {sw_32_32,   sw_16_16}") != 0)
        return 1;
    if(this->ntplCall("KeyType[Name=kt6] = {sw_128_128, sw_16_16}") != 0)
        return 1;

    if(this->ntplCall("KeyDef[Name=kd4; KeyType=kt4] = (Layer3Header[12]/32/32,  Layer4Header[0]/16/16)") != 0)
        return 1;
    if(this->ntplCall("keydef[Name=kd6; KeyType=kt6] = (Layer3Header[8]/128/128, Layer4Header[0]/16/16)") != 0)
        return 1;

    if(this->ntplCall("DefineMacro(\"LearnFilterCheck\", \"Layer2Protocol==EtherII and Layer3Protocol==$1\")") != 0)
        return 1;

    // Create filters for new flow's packages.
    if(this->ntplCall("Assign[StreamId=" STR(STREAM_ID_MISS) "; Descriptor=DYN1, Offset0=Layer3Header[12]] = LearnFilterCheck(ipv4) and Key(kd4, KeyID=" STR(KEY_ID_IPV4) ")==MISS") != 0)
        return 1;
    if(this->ntplCall("Assign[StreamId=" STR(STREAM_ID_MISS) "; Descriptor=DYN1, Offset0=Layer3Header[8]] = LearnFilterCheck(ipv6) and Key(kd6, KeyID=" STR(KEY_ID_IPV6) ")==MISS") != 0)
        return 1;

    // Create filters for unhandled packages, which will simply be counted by the application.
    if(this->ntplCall("Assign[StreamId=" STR(STREAM_ID_UNHA) "] = LearnFilterCheck(ipv4) and Key(kd4, KeyID=" STR(KEY_ID_IPV4) ")==UNHANDLED") != 0)
        return 1;
    if(this->ntplCall("Assign[StreamId=" STR(STREAM_ID_UNHA) "] = LearnFilterCheck(ipv6) and Key(kd6, KeyID=" STR(KEY_ID_IPV6) ")==UNHANDLED") != 0)
        return 1;

    if(this->ntplCall("Assign[StreamId=" STR(STREAM_ID_OLD) "] = LearnFilterCheck(ipv4) and Key(kd4, KeyID=" STR(KEY_ID_IPV4) ")==3") != 0)
        return 1;
    if(this->ntplCall("Assign[StreamId=" STR(STREAM_ID_OLD) "] = LearnFilterCheck(ipv6) and Key(kd6, KeyID=" STR(KEY_ID_IPV6) ")==3") != 0)
        return 1;
    if(this->ntplCall("Assign[StreamId=" STR(STREAM_ID_OLD) "] = LearnFilterCheck(ipv4) and Key(kd4, KeyID=" STR(KEY_ID_IPV4) ")==4") != 0)
        return 1;
    if(this->ntplCall("Assign[StreamId=" STR(STREAM_ID_OLD) "] = LearnFilterCheck(ipv6) and Key(kd6, KeyID=" STR(KEY_ID_IPV6) ")==4") != 0)
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
    this->status = NT_NetRxOpen(&(this->hNetRxMiss), "Miss packets stream", NT_NET_INTERFACE_PACKET, 1, -1);
    if(handleErrorStatus(this->status, "NT_NetRxOpen() failed") != 0)
        return 1;

    this->status = NT_NetRxOpen(&(this->hNetRxUnh), "Unhandled packets stream", NT_NET_INTERFACE_PACKET, 1, -1);
    if(handleErrorStatus(this->status, "NT_NetRxOpen() failed") != 0)
        return 1;

    this->status = NT_NetRxOpen(&(this->hNetRxOld), "Old packets stream", NT_NET_INTERFACE_PACKET, 1, -1);
    if(handleErrorStatus(this->status, "NT_NetRxOpen() failed") != 0)
        return 1;
    
    return 0;
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

    pkt_parser->captured_stats.protos_cnt = new uint16_t[ndpi_get_num_supported_protocols(this->ndpi_struct) + 1] ();

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
    
    if(this->setFilters() != 0){
        tracer->traceEvent(0, "Error initializing filters\n");
        delete(this);
        return 1;
    }

    if(this->setFlow() != 0){
        tracer->traceEvent(0, "Error initializing flows structure\n");
        delete(this);
        return 1;
    }

    if(this->setStream() != 0) {
        tracer->traceEvent(0, "Error initializing capture stream\n");
        delete(this);
        return 1;
    }

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

void NapatechReader::newPacket(void * header) {    
    NtNetBuf_t * hNetBuffer = (NtNetBuf_t *) header;   
 
    this->last_time = (uint64_t) NT_NET_GET_PKT_TIMESTAMP(* hNetBuffer);
    /*  Scan done every 15000 ms more or less   */    
    pkt_parser->captured_stats.total_wire_bytes += NT_NET_GET_PKT_CAP_LENGTH(* hNetBuffer);
    this->checkForIdleFlows();
}

/* ********************************** */

void NapatechReader::checkForIdleFlows()
{
    /*  Check if at least IDLE_SCAN_PERIOD passed since last scan   */
    if (this->last_idle_scan_time + IDLE_SCAN_PERIOD * 10000 < this->last_time || 
        pkt_parser->captured_stats.packets_captured - this->last_packets_scan > PACKET_SCAN_PERIOD) {
        for (this->idle_scan_index; this->idle_scan_index < this->max_idle_scan_index; ++this->idle_scan_index) {
            if(this->ndpi_flows_active[this->idle_scan_index] == nullptr)
                continue;
            ndpi_twalk(this->ndpi_flows_active[this->idle_scan_index], ndpi_idle_scan_walker, this);

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

                /*  Removes it from the active flows    */
                ndpi_tdelete(tmp_f, &this->ndpi_flows_active[this->idle_scan_index],
                             ndpi_workflow_node_cmp);

                if(tmp_f != nullptr)
                    flowFreer(tmp_f);

                this->cur_active_flows--;
            }
        }

        this->last_idle_scan_time = this->last_time;
        this->last_packets_scan = pkt_parser->captured_stats.packets_captured;

        /* Updating next max_idle_scan_index */
        this->max_idle_scan_index = ((this->idle_scan_index + this->max_idle_scan_index) % this->max_active_flows) + 1;
    }
}

/* ********************************** */

int NapatechReader::startRead()
{
    std::thread receiverThread1(taskReceiverMiss, "flowmatch_example_receiver_net_rx_miss", STREAM_ID_MISS);
    std::thread receiverThread2(taskReceiverCounter, "flowmatch_example_receiver_net_rx_unhandled", STREAM_ID_UNHA);
    std::thread receiverThread3(taskReceiverOld, "flowmatch_example_receiver_net_rx_total", STREAM_ID_OLD);

    
}

void taskReceiverMiss(const char* streamName, uint32_t streamId)
{
    while(this->error_or_eof == 0) {
        // Get package from rx stream.
        this->status = NT_NetRxGetNextPacket(this->hNetRxMiss, &(this->hNetBufferMiss), -1);
        
        if(this->status == NT_STATUS_TIMEOUT || status == NT_STATUS_TRYAGAIN) 
            continue;

        if(this->status == NT_ERROR_NT_TERMINATING)
	    break;

        if(handleErrorStatus(this->status, "Error while sniffing next packet") != 0) {
            this->error_or_eof = 1;
            return 1;
        }

        pkt_parser->processPacket(this, &hNetBufferMiss, streamId);
    }	

    this->error_or_eof = 1;
    return 0;
}

void taskReceiverCounter(const char* streamName, uint32_t streamId)
{
    while(this->error_or_eof == 0) {
        // Get package from rx stream.
        this->status = NT_NetRxGetNextPacket(this->hNetRxUnh, &(this->hNetBufferUnh), -1);
        
        if(this->status == NT_STATUS_TIMEOUT || status == NT_STATUS_TRYAGAIN) 
            continue;

        if(this->status == NT_ERROR_NT_TERMINATING)
	    break;

        if(handleErrorStatus(this->status, "Error while sniffing next packet") != 0) {
            this->error_or_eof = 1;
            return 1;
        }

        pkt_parser->processPacket(this, &hNetBufferUnh, streamId);
    }	

    this->error_or_eof = 1;
    return 0;
}

void taskReceiverOld(const char* streamName, uint32_t streamId)
{
    while(this->error_or_eof == 0) {
        // Get package from rx stream.
        this->status = NT_NetRxGetNextPacket(this->hNetRxOld, &(this->hNetBufferOld), -1);
        
        if(this->status == NT_STATUS_TIMEOUT || status == NT_STATUS_TRYAGAIN) 
            continue;

        if(this->status == NT_ERROR_NT_TERMINATING)
	    break;

        if(handleErrorStatus(this->status, "Error while sniffing next packet") != 0) {
            this->error_or_eof = 1;
            return 1;
        }

        pkt_parser->processPacket(this, &hNetBufferOld, streamId);
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

void NapatechReader::printStats()
{
    long long unsigned int avg_pkt_size = 0;
    long long unsigned int breed_stats[NUM_BREEDS] = { 0 };
    char buf[32];
    //long long unsigned int breed_stats[NUM_BREEDS] = { 0 };

    tracer->traceEvent(2, "\tTraffic statistics:\r\n");
    tracer->traceEvent(2, "\t\tEthernet bytes:             %-20llu (includes ethernet CRC/IFC/trailer)\n",
                            pkt_parser->captured_stats.total_wire_bytes);
    tracer->traceEvent(2, "\t\tDiscarded bytes:            %-20llu\n",
                            pkt_parser->captured_stats.discarded_bytes);
    tracer->traceEvent(2, "\t\tIP packets:                 %-20llu of %llu packets total\n",
                            pkt_parser->captured_stats.ip_pkts,
                            pkt_parser->captured_stats.packets_captured);

    /* In order to prevent Floating point exception in case of no traffic*/
    if(pkt_parser->captured_stats.ip_bytes && pkt_parser->captured_stats.packets_captured)
        avg_pkt_size = pkt_parser->captured_stats.ip_bytes/pkt_parser->captured_stats.packets_captured;

    tracer->traceEvent(2, "\t\tIP bytes:                   %-20llu (avg pkt size %u bytes)\n",
                            pkt_parser->captured_stats.ip_bytes, avg_pkt_size);

    tracer->traceEvent(2, "\t\tUnique flows:               %-20u\n", pkt_parser->captured_stats.total_flows_captured);

    tracer->traceEvent(2, "\t\tTCP Packets:                %-20lu\n", pkt_parser->captured_stats.tcp_pkts);
    tracer->traceEvent(2, "\t\tUDP Packets:                %-20lu\n", pkt_parser->captured_stats.udp_pkts);

    char when[64];
    struct tm result;

    strftime(when, sizeof(when), "%d/%b/%Y %H:%M:%S", localtime_r(&pkt_parser->captured_stats.pcap_start.tv_sec, &result));
    tracer->traceEvent(2, "\t\tAnalysis begin:             %s\n", when);

    strftime(when, sizeof(when), "%d/%b/%Y %H:%M:%S", localtime_r(&pkt_parser->captured_stats.pcap_end.tv_sec, &result));
    tracer->traceEvent(2, "\t\tAnalysis end:               %s\n", when);

    tracer->traceEvent(2, "\t\tDetected flow protos:       %-20u\n", pkt_parser->captured_stats.detected_flow_protocols);
    tracer->traceEvent(2, "\t\tGuessed flow protos:        %-20u\n", pkt_parser->captured_stats.guessed_flow_protocols);
    tracer->traceEvent(2, "\t\tUnclassified flow protos:   %-20u\r\n", pkt_parser->captured_stats.unclassified_flow_protocols);


    tracer->traceEvent(2, "\tDetected protocols:\r\n");

    for(u_int32_t i = 0; i <= ndpi_get_num_supported_protocols(this->ndpi_struct); i++) {
        ndpi_protocol_breed_t breed = ndpi_get_proto_breed((this->ndpi_struct), i);
        if(pkt_parser->captured_stats.protos_cnt[i] > 0) {
            breed_stats[i] += pkt_parser->captured_stats.protos_cnt[i];

            tracer->traceEvent(2, "\t\t%-20s flows: %-13u\r\n",
                ndpi_get_proto_name((this->ndpi_struct), i), pkt_parser->captured_stats.protos_cnt[i]);
        }
    }



    tracer->traceEvent(2, "\tProtocol statistics:\n");

    for(u_int32_t i = 0; i < NUM_BREEDS; i++) {
      if(breed_stats[i] > 0) {
	    tracer->traceEvent(2, "\t\t%-20s flows: %-13u\n",
                ndpi_get_proto_breed_name(this->ndpi_struct, ndpi_get_proto_breed(this->ndpi_struct, i)),
                breed_stats[i]);
      }
    }
}

/* ********************************** */

int NapatechReader::newFlow(FlowInfo * & flow_to_process) {
    if (this->cur_active_flows == this->max_active_flows) {
        tracer->traceEvent(0, "[%8llu] max flows to track reached: %llu, idle: %llu\n",
                                pkt_parser->captured_stats.packets_captured, this->max_active_flows, this->cur_idle_flows);
        return -1;
    }

    flow_to_process = (FlowInfo *)ndpi_malloc(sizeof(*flow_to_process));
    if (flow_to_process == nullptr) {
        tracer->traceEvent(0, "[%8llu] Not enough memory for flow info\n",
                                pkt_parser->captured_stats.packets_captured);
        return -1;
    }

    this->cur_active_flows++;
    this->total_active_flows++;

    return 0;
}

/* ********************************** */
