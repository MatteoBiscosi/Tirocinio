//
// Created by matteo on 09/07/2020.
//

#include <ndpi_light_includes.h>
#include <pcap_reader.h>

/* ********************************** */

//Constructors
PcapReader::PcapReader() : file_or_device(nullptr) {
    file_or_device = nullptr;
}

PcapReader::PcapReader(char const * const dst) : file_or_device(nullptr) {
    file_or_device = dst;
}

int PcapReader::prova() {
    std::cout << this->file_or_device << "\n";
}

/* ********************************** */

int PcapReader::initFileOrDevice() {
//Initializing the pcap_handler, needed to read from a file or a device
    if (access(file_or_device, R_OK) != 0 && errno == ENOENT) {
        this->pcap_handle = pcap_open_live(file_or_device, /* 1536 */ 65535, 1, 250, pcap_error_buffer);
    } else {
        this->pcap_handle = pcap_open_offline_with_tstamp_precision(file_or_device, PCAP_TSTAMP_PRECISION_MICRO,
                                                                        pcap_error_buffer);
    }

    if(this->pcap_handle == nullptr) {
        std::cerr << "Error, pcap_open_live / pcap_open_offline_with_tstamp_precision: "
                  << pcap_error_buffer << "\n";

        return -1;
    }

    if(this->init_module() != 0) {
        std::cerr << "Error initializing detection module\n";
        return -1;
    }

    if(this->init_infos() != 0) {

    }
}

/* ********************************** */

int PcapReader::init_module() {
//Initialize module's infos
    ndpi_init_prefs init_prefs = ndpi_no_prefs;
    this->ndpi_struct = ndpi_init_detection_module(init_prefs);
    if (this->ndpi_struct == nullptr) {
        return -1;
    }

    return 0;
}

/* ********************************** */

int PcapReader::init_infos() {
//Initialize flow's infos
    this->total_active_flows = 0;
    this->max_active_flows = MAX_FLOW_ROOTS_PER_THREAD;
    workflow->ndpi_flows_active = (void **)ndpi_calloc(workflow->max_active_flows, sizeof(void *));
    if (workflow->ndpi_flows_active == NULL) {
        free_workflow(&workflow);
        return NULL;
    }

    workflow->total_idle_flows = 0;
    workflow->max_idle_flows = MAX_IDLE_FLOWS_PER_THREAD;
    workflow->ndpi_flows_idle = (void **)ndpi_calloc(workflow->max_idle_flows, sizeof(void *));
    if (workflow->ndpi_flows_idle == NULL) {
        free_workflow(&workflow);
        return NULL;
    }

    NDPI_PROTOCOL_BITMASK protos;
    NDPI_BITMASK_SET_ALL(protos);
    ndpi_set_protocol_detection_bitmask2(workflow->ndpi_struct, &protos);
    ndpi_finalize_initalization(workflow->ndpi_struct);
}

/* ********************************** */