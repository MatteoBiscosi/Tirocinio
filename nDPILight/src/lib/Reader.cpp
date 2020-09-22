#include "ndpi_light_includes.h"




/* ********************************** */

Reader::Reader(char *log_path, const char *type)
{
    this->log_path = nullptr;
    if(log_path != nullptr)
    	this->log_path = log_path;

    this->type = type;
    this->ndpi_flows_active = nullptr;
    this->error_or_eof = 0;
    this->ndpi_struct = nullptr;
    this->last_idle_scan_time = 0;
    this->last_time = 0;
    this->idle_scan_index = 0;
    this->newFlowCheck = false;
    this->cur_active_flows = 0;
    this->max_active_flows = MAX_FLOW_ROOTS_PER_THREAD; 
    this->max_idle_scan_index = MAX_FLOW_ROOTS_PER_THREAD / 8;
}

/* ********************************** */

Reader::~Reader()
{
    if (this->ndpi_struct != nullptr) {
        ndpi_exit_detection_module(this->ndpi_struct);
    }
}   

/* ********************************** */

int Reader::newFlow(FlowInfo * & flow_to_process) {
    if (this->cur_active_flows == this->max_active_flows) {
        tracer->traceEvent(0, "[10] max flows to track reached: %llu, idle: %llu\n",
                                this->max_active_flows, this->cur_idle_flows);
        return -1;
    }

    flow_to_process = new FlowInfo();
    if (flow_to_process == nullptr) {
        tracer->traceEvent(0, "[10] Not enough memory for flow info\n");
        return -1;
    }

    this->cur_active_flows++;
    this->total_active_flows++;

    return 0;
}

/* ********************************** */
