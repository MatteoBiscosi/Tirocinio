
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
    std::cout << "Prova 2\n";
    
    NtNetBuf_t * hNetBuffer = (NtNetBuf_t *) header;   
 
    this->last_time = (uint64_t) NT_NET_GET_PKT_TIMESTAMP(* hNetBuffer);
    /*  Scan done every 15000 ms more or less   */    
    pkt_parser->captured_stats.total_wire_bytes += NT_NET_GET_PKT_CAP_LENGTH(* hNetBuffer);
    this->checkForIdleFlows();
}

/* ********************************** */

void NapatechReader::checkForIdleFlows()
{
	return;
	this->last_idle_scan_time + IDLE_SCAN_PERIOD * 10000 < this->last_time;
    printf("Prova check\n");    

    /*  Check if at least IDLE_SCAN_PERIOD passed since last scan   */
    if (this->last_idle_scan_time + IDLE_SCAN_PERIOD * 10000 < this->last_time || 
        pkt_parser->captured_stats.packets_captured - this->last_packets_scan > PACKET_SCAN_PERIOD) {
        for (this->idle_scan_index; this->idle_scan_index < this->max_idle_scan_index; ++this->idle_scan_index) {
            if(this->ndpi_flows_active[this->idle_scan_index] == nullptr)
                continue;
	    printf("Prova 2\n");
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
	printf("Prova fuori check");
        this->last_idle_scan_time = this->last_time;
        this->last_packets_scan = pkt_parser->captured_stats.packets_captured;

        /* Updating next max_idle_scan_index */
        this->max_idle_scan_index = ((this->idle_scan_index + this->max_idle_scan_index) % this->max_active_flows) + 1;
    }
}

/* ********************************** */

int NapatechReader::startRead()
{
    while(this->error_or_eof == 0) {
        // Get package from rx stream.
        this->status = NT_NetRxGetNextPacket(this->hNetRx, &(this->hNetBuffer), -1);
        
        if(this->status == NT_STATUS_TIMEOUT || status == NT_STATUS_TRYAGAIN) 
            continue;

        if(this->status == NT_ERROR_NT_TERMINATING)
	    break;

        if(handleErrorStatus(this->status, "Error while sniffing next packet") != 0) {
            this->error_or_eof = 1;
            return 1;
        }

	std::cout << "Prova 1\n";

        printf("%llu", NT_NET_GET_PKT_TIMESTAMP(hNetBuffer));
        pkt_parser->processPacket(this, &hNetBuffer, nullptr);
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
