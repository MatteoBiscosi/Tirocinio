//
// Created by matteo on 09/07/2020.
//

#include <ndpi_light_includes.h>
#include <pcap_reader.h>

/* ********************************** */

/*  Constructors    */
PcapReader::PcapReader() : file_or_device(nullptr)
{
    file_or_device = nullptr;
}

PcapReader::PcapReader(char const * const dst) : file_or_device(nullptr)
{
    file_or_device = dst;
}

/* ********************************** */

void PcapReader::freeReader()
/*  Sort of destructor  */
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

int PcapReader::initInfos()
/*  Initialize flow's infos */
{
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

void PcapReader::printInfos()
/*  Prints infos about the packets and flows */
{
    std::cout << "Total packets captured.: " << this->packets_captured << "\n";
    std::cout << "Total packets processed: " << this->packets_processed << "\n";
    std::cout << "Total layer4 data size.: " << this->total_l4_data_len << "\n";
    std::cout << "Total flows captured...: " << this->total_active_flows << "\n";
    std::cout << "Total flows timed out..: " << this->total_idle_flows << "\n";
    std::cout << "Total flows detected...: " << this->detected_flow_protocols << "\n";
}

/* ********************************** */

static void process_helper(uint8_t * const args,
                           pcap_pkthdr const * const header,
                           uint8_t const * const packet)
/*  Utility function used to call class-specific process packet */
{
    auto * const reader_thread = (PcapReader *) args;
    reader_thread->processPacket(nullptr, header, packet);
}

/* ********************************** */

int PcapReader::startRead()
/*  Function used to start the pcap_loop    */
{
    if(this->pcap_handle != nullptr) {
        if (pcap_loop(this->pcap_handle, -1,
                      &process_helper, (uint8_t *) this) == PCAP_ERROR) {

            std::cerr << "Error while reading using Pcap: "
                 << pcap_geterr(this->pcap_handle) << "\n";

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
        this->pcap_handle = nullptr;
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

static void ndpi_idle_scan_walker(void const * const A, ndpi_VISIT which, int depth, void * const user_data)
/*  Function used to search for idle flows  */
{
    auto * const workflow = (PcapReader *)user_data;
    auto * const flow = *(FlowInfo **)A;

    (void)depth;

    if (workflow == nullptr || flow == nullptr) {
        return;
    }

    /* Is this limit needed?
    if (workflow->cur_idle_flows == MAX_IDLE_FLOWS_PER_THREAD) {
        return;
    }
    */

    if (which == ndpi_preorder || which == ndpi_leaf) {
        if ((flow->flow_fin_ack_seen == 1 && flow->flow_ack_seen == 1) ||
            flow->last_seen + MAX_IDLE_TIME < workflow->getLastTime())
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

static int ndpi_workflow_node_cmp(void const * const A, void const * const B)
/*  Checks if two nodes of the tree, A and B, are equals    */
{
    auto * const flow_info_a = (FlowInfo *)A;
    auto * const flow_info_b = (FlowInfo *)B;

    /*  Check hashval   */
    if (flow_info_a->hashval < flow_info_b->hashval) {
        return(-1);
    } else if (flow_info_a->hashval > flow_info_b->hashval) {
        return(1);
    }

    /*  Flows have the same hash, check l4_protocol */
    if (flow_info_a->l4_protocol < flow_info_b->l4_protocol) {
        return(-1);
    } else if (flow_info_a->l4_protocol > flow_info_b->l4_protocol) {
        return(1);
    }

    /*  Have same hashval and l4, check l3 ip   */
    if (flow_info_a->ipTuplesEqual(flow_info_b) != 0 &&
        flow_info_a->src_port == flow_info_b->src_port &&
        flow_info_a->dst_port == flow_info_b->dst_port)
    {
        return(0);
    }

    /*  Last check, l3 ip and port  */
    return flow_info_a->ipTuplesCompare(flow_info_b);
}

/* ********************************** */

void PcapReader::checkForIdleFlows()
/*  Scan used to check if there are idle flows  */
{
    /*  Check if at least IDLE_SCAN_PERIOD passed since last scan   */
    if (this->last_idle_scan_time + IDLE_SCAN_PERIOD < this->last_time) {
        for (size_t idle_scan_index = 0; idle_scan_index < this->max_active_flows; ++idle_scan_index) {
            ndpi_twalk(this->ndpi_flows_active[idle_scan_index], ndpi_idle_scan_walker, this);

            /*  Removes all idle flows that were copied into ndpi_flows_idle from the ndpi_twalk    */
            while (this->cur_idle_flows > 0) {
                /*  Get the flow    */
                auto * const tmp_f =
                        (FlowInfo *)this->ndpi_flows_idle[--this->cur_idle_flows];
                if (tmp_f->flow_fin_ack_seen == 1) {
                    std::cout << "Free fin flow with id " << tmp_f->flow_id << "\n";
                } else {
                    std::cout << "Free idle flow with id " << tmp_f->flow_id << "\n";
                }

                /*  Removes it from the active flows    */
                ndpi_tdelete(tmp_f, &this->ndpi_flows_active[idle_scan_index],
                                 ndpi_workflow_node_cmp);
                tmp_f->infoFreer();
                this->cur_active_flows--;
            }
        }

        this->last_idle_scan_time = this->last_time;
    }
}

/* ********************************** */

void PcapReader::processPacket(uint8_t * const args,
                                pcap_pkthdr const * const header,
                                uint8_t const * const packet)
/*  This function is called every time a new packets appears;
 *  it process all the packets, adding new flows, updating infos, ecc.  */
{
    FlowInfo flow;

    size_t hashed_index;
    void * tree_result;
    FlowInfo * flow_to_process;

    int direction_changed = 0;
    struct ndpi_id_struct * ndpi_src;
    struct ndpi_id_struct * ndpi_dst;

    const struct ndpi_ethhdr * ethernet;
    const struct ndpi_iphdr * ip;
    struct ndpi_ipv6hdr * ip6;

    uint64_t time_ms;
    const uint16_t eth_offset = 0;
    uint16_t ip_offset;
    uint16_t ip_size;

    const uint8_t * l4_ptr = nullptr;
    uint16_t l4_len = 0;

    uint16_t type;
    int thread_index = INITIAL_THREAD_HASH; /* generated with `dd if=/dev/random bs=1024 count=1 |& hd' */


    this->packets_captured++;
    time_ms = ((uint64_t) header->ts.tv_sec) * TICK_RESOLUTION + header->ts.tv_usec / (1000000 / TICK_RESOLUTION);
    this->last_time = time_ms;


    /*  Scan done every 10000 ms more or less   */
    this->checkForIdleFlows();

}

/* ********************************** */
    /*  GETTERS AND SETTERS */

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