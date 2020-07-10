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

/* ********************************** */

void PcapReader::freeReader()
//Sort of destructor
{
    if (this->pcap_handle != nullptr) {
        pcap_close(this->pcap_handle);
        this->pcap_handle = nullptr;
    }

    if (this->ndpi_struct != nullptr) {
        ndpi_exit_detection_module(this->ndpi_struct);
    }
    for(size_t i = 0; i < this->max_active_flows; i++) {
        ndpi_tdestroy(this->ndpi_flows_active[i], ndpi_flow_info_freer);
    }
    ndpi_free(this->ndpi_flows_active);
    ndpi_free(this->ndpi_flows_idle);
    ndpi_free(this);
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
        this->freeReader();
        return -1;
    }

    if(this->initModule() != 0) {
        std::cerr << "Error initializing detection module\n";
        this->freeReader();
        return -1;
    }

    if(this->initInfos() != 0) {
        std::cerr << "Error initializing structure infos\n";
        this->freeReader();
        return -1;
    }
}

/* ********************************** */

int PcapReader::initModule() {
//Initialize module's infos
    ndpi_init_prefs init_prefs = ndpi_no_prefs;
    this->ndpi_struct = ndpi_init_detection_module(init_prefs);
    if (this->ndpi_struct == nullptr) {
        return -1;
    }

    return 0;
}

/* ********************************** */

int PcapReader::initInfos() {
//Initialize flow's infos

    this->total_active_flows = 0; /* First initialize active flow's infos */
    this->max_active_flows = MAX_FLOW_ROOTS_PER_THREAD;
    this->ndpi_flows_active = (void **)ndpi_calloc(this->max_idle_flows, sizeof(void *))
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
}

/* ********************************** */

void PcapReader::printInfos() {
/*  Prints infos about the packets and flows */

    std::cout << "Total packets captured.: " << this->packets_captured << "\n";
    std::cout << "Total packets processed: " << this->packets_processed << "\n";
    std::cout << "Total layer4 data size.: " << this->total_l4_data_len << "\n";
    std::cout << "Total flows captured...: " << this->total_active_flows << "\n";
    std::cout << "Total flows timed out..: " << this->total_idle_flows << "\n";
    std::cout << "Total flows detected...: " << this->detected_flow_protocols << "\n";
}