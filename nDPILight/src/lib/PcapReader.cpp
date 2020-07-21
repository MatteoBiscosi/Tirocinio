//
// Created by matteo on 09/07/2020.
//


#include "ndpi_light_includes.h"



/* ********************************** */

/*  Constructors and Destructors    */
PcapReader::PcapReader() : file_or_device(nullptr)
{
    file_or_device = nullptr;
}

PcapReader::PcapReader(char const * const dst) : file_or_device(nullptr)
{
    file_or_device = dst;
}


PcapReader::~PcapReader()
/*  Destructor  */
{
    if(this->ndpi_struct != nullptr)
        free(ndpi_struct);
}

/* ********************************** */

void PcapReader::freeReader()
/*  Sort of destructor  */
{
    if(this == nullptr)
        return;

    if (this->pcap_handle != nullptr) {
        pcap_close(this->pcap_handle);
        this->pcap_handle = nullptr;
    }

    if (this->ndpi_struct != nullptr) {
        ndpi_exit_detection_module(this->ndpi_struct);
    }

    for(size_t i = 0; i < this->max_active_flows; i++) {
        ndpi_tdestroy(this->ndpi_flows_active[i], flowFreer);
    }

    if(this->ndpi_flows_active != nullptr)
        ndpi_free(this->ndpi_flows_active);
    if(this->ndpi_flows_idle != nullptr)
        ndpi_free(this->ndpi_flows_idle);
}

/* ********************************** */

int PcapReader::initModule()
/*  Initialize module's infos   */
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
/*  Initializing the pcap_handler, needed to read from a file or a device   */
{
    if (access(file_or_device, R_OK) != 0 && errno == ENOENT) {
        this->pcap_handle = pcap_open_live(file_or_device, /* 1536 */ 65535, 1, 250, pcap_error_buffer);
    } else {
        this->pcap_handle = pcap_open_offline_with_tstamp_precision(file_or_device, PCAP_TSTAMP_PRECISION_MICRO,
                                                                    pcap_error_buffer);
    }

    if(this->pcap_handle == nullptr) {
        tracer->traceEvent(0, "Error, pcap_open_live\
                                pcap_open_offline_with_tstamp_precision:\
                                \n%s\n\n", pcap_error_buffer);
        this->freeReader();
        return -1;
    }

    if(this->initModule() != 0) {
        tracer->traceEvent(0, "Error initializing detection module\n");
        this->freeReader();
        return -1;
    }

    if(this->initInfos() != 0) {
        tracer->traceEvent(0, "Error initializing structure infos\n");
        this->freeReader();
        return -1;
    }

    return 0;
}

/* ********************************** */

int PcapReader::initInfos()
/*  Initialize flow's infos */
{
    this->total_active_flows = 0; /* First initialize active flow's infos */
    this->max_active_flows = MAX_FLOW_ROOTS_PER_THREAD;
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

    return 0;
}

/* ********************************** */

void PcapReader::printInfos()
/*  Prints infos about the packets and flows */
{
    tracer->traceEvent(2, "Total packets captured.: %llu\n", pkt_parser.getPktCaptured());
    tracer->traceEvent(2, "Total packets processed: %llu\n", this->packets_processed);
    tracer->traceEvent(2, "Total layer4 data size.: %llu\n", this->total_l4_data_len);
    tracer->traceEvent(2, "Total flows captured...: %llu\n", this->total_active_flows);
    tracer->traceEvent(2, "Total flows timed out..: %llu\n", this->total_idle_flows);
    tracer->traceEvent(2, "Total flows detected...: %llu\r\n\r\n\r\n", this->detected_flow_protocols);

    this->freeReader();
}

/* ********************************** */

int PcapReader::startRead()
/*  Function used to start the pcap_loop    */
{
    if(this->pcap_handle != nullptr) {
        if (pcap_loop(this->pcap_handle, -1,
                      &process_helper, (uint8_t *) this) == PCAP_ERROR) {

            tracer->traceEvent(0, "Error while reading using Pcap: %s\n", pcap_geterr(this->pcap_handle));

            this->error_or_eof = 1;

            return -1;
        }
    }

    return -1;
}

/* ********************************** */

void PcapReader::stopRead()
/*  Function used to set pcap to nullptr    */
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
/*  Scan used to check if there are idle flows  */
{
    /*  Check if at least IDLE_SCAN_PERIOD passed since last scan   */
    if (this->last_idle_scan_time + IDLE_SCAN_PERIOD < this->last_time) {
        for (size_t idle_scan_index = 0; idle_scan_index < this->max_active_flows; ++idle_scan_index) {
            if(this->ndpi_flows_active[idle_scan_index] == nullptr)
                continue;

            ndpi_twalk(this->ndpi_flows_active[idle_scan_index], ndpi_idle_scan_walker, this);

            /*  Removes all idle flows that were copied into ndpi_flows_idle from the ndpi_twalk    */
            while (this->cur_idle_flows > 0) {
                /*  Get the flow    */
                FlowInfo * const tmp_f =
                        (FlowInfo *)this->ndpi_flows_idle[--this->cur_idle_flows];

                if(tmp_f == nullptr)
                    continue;

                if (tmp_f->flow_fin_ack_seen == 1) {
                    tracer->traceEvent(2, "[%4u] Freeing flow due to fin\n", tmp_f->flow_id);
                } else {
                    tracer->traceEvent(2, "[%4u] Freeing idle flow\n", tmp_f->flow_id);
                }

                /*  Removes it from the active flows    */
                ndpi_tdelete(tmp_f, &this->ndpi_flows_active[idle_scan_index],
                             ndpi_workflow_node_cmp);

                if(tmp_f != nullptr)
                    flowFreer(tmp_f);

                this->cur_active_flows--;
            }
        }

        this->last_idle_scan_time = this->last_time;
    }
}

/* ********************************** */

void PcapReader::newPacket(pcap_pkthdr const * const header) {
    uint64_t time_ms = ((uint64_t) header->ts.tv_sec) * TICK_RESOLUTION + header->ts.tv_usec / (1000000 / TICK_RESOLUTION);
    this->last_time = time_ms;
    /*  Scan done every 10000 ms more or less   */
    this->checkForIdleFlows();
}

int PcapReader::newFlow(FlowInfo * & flow_to_process) {
    if (this->cur_active_flows == this->max_active_flows) {
        tracer->traceEvent(0, "[%8llu] max flows to track reached: %llu, idle: %llu\n",
                                pkt_parser.getPktCaptured(), this->max_active_flows, this->cur_idle_flows);
        return -1;
    }

    flow_to_process = (FlowInfo *)ndpi_malloc(sizeof(*flow_to_process));
    if (flow_to_process == nullptr) {
        tracer->traceEvent(0, "[%8llu] Not enough memory for flow info\n",
                                pkt_parser.getPktCaptured());
        return -1;
    }

    this->cur_active_flows++;
    this->total_active_flows++;

    return 0;
}

/* ********************************** */
/*  GETTERS AND SETTERS */

void PcapReader::incrL4Ctrs(uint16_t& l4_len) {
    this->packets_processed++;
    this->total_l4_data_len += l4_len;
}

void PcapReader::incrTotalIdleFlows()
{
    this->total_idle_flows++;
}

void PcapReader::incrCurIdleFlows()
{
    this->cur_idle_flows++;
}

uint64_t PcapReader::getLastTime()
{
    return this->last_time;
}

void **PcapReader::getNdpiFlowsIdle()
{
    return this->ndpi_flows_idle;
}

unsigned long long int PcapReader::getCurIdleFlows()
{
    return this->cur_idle_flows;
}

/* ********************************** */