
#include "ndpi_light_includes.h"



/* ********************************** */

/*  Constructors and Destructors    */
PcapReader::PcapReader(char *log_path, const char *type) : Reader(log_path, type) 
{
    file_or_device = nullptr;
}

PcapReader::PcapReader(char *log_path, const char *type, const char * dst) : Reader(log_path, type) 
{
    file_or_device = dst;
}


PcapReader::~PcapReader()
{
    if (this->pcap_handle != nullptr) {
        pcap_close(this->pcap_handle);
        this->pcap_handle = nullptr;
    }
}   

/* ********************************** */

int PcapReader::initModule()
{
    ndpi_init_prefs init_prefs = ndpi_no_prefs;
    this->ndpi_struct = ndpi_init_detection_module(init_prefs);
    if (this->ndpi_struct == nullptr) {
        return -1;
    }

    return 0;
}

/* ********************************** */

int PcapReader::initFileOrDevice()
{
    if(this->log_path != nullptr) {
	this->pkt_parser = new PcapDissector(this->log_path, this->type);
    } else {
        this->pkt_parser = new PcapDissector(this->type);
    }

    if (access(file_or_device, R_OK) != 0 && errno == ENOENT) {
        this->pcap_handle = pcap_open_live(file_or_device, /* 1536 */ 65535, 1, 250, pcap_error_buffer);
    } else {
        this->pcap_handle = pcap_open_offline_with_tstamp_precision(file_or_device, PCAP_TSTAMP_PRECISION_MICRO,
                                                                    pcap_error_buffer);
    }

    if(this->pcap_handle == nullptr) {
        tracer->traceEvent(0, "Error, pcap_open_live pcap_open_offline_with_tstamp_precision:\n%s\n\n",
                            pcap_error_buffer);
        delete(this);
        return -1;
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

int PcapReader::initInfos()
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

void PcapReader::printStats()
{
    pkt_parser->printStats((Reader *) this);
}

/* ********************************** */

int PcapReader::startRead()
{
    tracer->traceEvent(2, "\tAnalysis started\r\n\r\n");

    if(this->pcap_handle != nullptr) {
        if (pcap_loop(this->pcap_handle, -1,
                      &process_helper, (uint8_t *) this) == PCAP_ERROR) {

            tracer->traceEvent(0, "Error while reading using Pcap: %s\n", pcap_geterr(this->pcap_handle));

            this->error_or_eof = 1;

            return -1;
        }

        this->error_or_eof = 1;
    }

    return -1;
}

/* ********************************** */

void PcapReader::stopRead()
{
    if (this->pcap_handle != nullptr) {
        pcap_breakloop(this->pcap_handle);
    }
}

/* ********************************** */

int PcapReader::checkEnd()
{
    if(this->error_or_eof == 0)
        return 0;

    return -1;
}

/* ********************************** */

void PcapReader::checkForIdleFlows()
{
    /*  Check if at least IDLE_SCAN_PERIOD passed since last scan   */
    if (this->last_idle_scan_time + IDLE_SCAN_PERIOD < this->last_time || 
        pkt_parser->getPktsCaptured() - this->last_packets_scan > PACKET_SCAN_PERIOD) {
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

void PcapReader::newPacket(void * header) {
    pcap_pkthdr const * const header_tmp = (pcap_pkthdr const * const) header;

    uint64_t time_ms = ((uint64_t) header_tmp->ts.tv_sec) * TICK_RESOLUTION + header_tmp->ts.tv_usec / (1000000 / TICK_RESOLUTION);
    this->last_time = time_ms; 
    /*  Scan done every 15000 ms more or less   */    
    pkt_parser->incrWireBytes(header_tmp->caplen);
    this->checkForIdleFlows();
}

/*  GETTERS AND SETTERS */
/* ********************************** */

void PcapReader::incrTotalIdleFlows()
{
    this->total_idle_flows++;
}

/* ********************************** */

void PcapReader::incrCurIdleFlows()
{
    this->cur_idle_flows++;
}

/* ********************************** */

uint64_t PcapReader::getLastTime()
{
    return this->last_time;
}

/* ********************************** */

void **PcapReader::getNdpiFlowsIdle()
{
    return this->ndpi_flows_idle;
}

/* ********************************** */

unsigned long long int PcapReader::getCurIdleFlows()
{
    return this->cur_idle_flows;
}

/* ********************************** */
