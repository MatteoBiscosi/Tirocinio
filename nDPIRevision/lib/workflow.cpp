//
// Created by matteo on 08/07/2020.
//

#include "workflow.h"


class nDPI_workflow : nDPI_workflow_if {
public:
    pcap_t *pcap_handle;

    uint8_t error_or_eof: 1;

    //Unused elements
    uint8_t reserved_00: 7;
    uint8_t reserved_01[3];

    unsigned long long int packets_captured;
    unsigned long long int packets_processed;
    unsigned long long int total_l4_data_len;
    unsigned long long int detected_flow_protocols;

    uint64_t last_idle_scan_time;
    uint64_t last_time;

    void **ndpi_flows_active;
    unsigned long long int max_active_flows;
    unsigned long long int cur_active_flows;
    unsigned long long int total_active_flows;

    void **ndpi_flows_idle;
    unsigned long long int max_idle_flows;
    unsigned long long int cur_idle_flows;
    unsigned long long int total_idle_flows;

    struct ndpi_detection_module_struct *ndpi_struct;
public:
    static void free_workflow(nDPI_workflow **const workflow)
    /*
     *  "Destructor" of nDPI_workflow struct
     */
    {
        nDPI_workflow *const w = *workflow;

        if (w == nullptr) {
            return;
        }

        //Closing the capture file/device
        if (w->pcap_handle != nullptr) {
            pcap_close(w->pcap_handle);
            w->pcap_handle = nullptr;
        }

        //Exiting the detection module
        if (w->ndpi_struct != nullptr) {
            ndpi_exit_detection_module(w->ndpi_struct);
        }

        //Freeing the various flows
        for (size_t i = 0; i < w->max_active_flows; i++) {
            ndpi_tdestroy(w->ndpi_flows_active[i], nDPI_flow_info::ndpi_flow_info_freer);
        }
        ndpi_free(w->ndpi_flows_active);
        ndpi_free(w->ndpi_flows_idle);
        ndpi_free(w);
        *workflow = nullptr;
    }


    static nDPI_workflow *init_workflow(char const *const file_or_device)
    /*
     * Initializer of nDPI_workflow struct
     */
    {
        char pcap_error_buffer[PCAP_ERRBUF_SIZE];

        nDPI_workflow *workflow = (nDPI_workflow *) ndpi_calloc(1, sizeof(*workflow));

        if (workflow == nullptr) {
            return nullptr;
        }

        if (access(file_or_device, R_OK) != 0 && errno == ENOENT) {
            //trying to open a device
            workflow->pcap_handle = pcap_open_live(file_or_device, /* 1536 */ 65535, 1, 250, pcap_error_buffer);
        } else {
            //if opening the device fails, try to open a saved capture file
            workflow->pcap_handle = pcap_open_offline_with_tstamp_precision(file_or_device, PCAP_TSTAMP_PRECISION_MICRO,
                                                                            pcap_error_buffer);
        }

        //if both opening fails, return an error
        if (workflow->pcap_handle == nullptr) {
            std::cerr << "error during pcap_open_live / pcap_open_offline_with_tstamp_precision: "
                      << pcap_error_buffer << "\n";
            free_workflow(&workflow);
            return nullptr;
        }

        //Init the detection module
        ndpi_init_prefs init_prefs = ndpi_no_prefs;
        workflow->ndpi_struct = ndpi_init_detection_module(init_prefs);
        if (workflow->ndpi_struct == nullptr) {
            //Error while initializing the detection module
            free_workflow(&workflow);
            return nullptr;
        }

        //Init the active flows per thread
        workflow->total_active_flows = 0;
        workflow->max_active_flows = MAX_FLOW_ROOTS_PER_THREAD;
        workflow->ndpi_flows_active = (void **) ndpi_calloc(workflow->max_active_flows, sizeof(void *));
        if (workflow->ndpi_flows_active == nullptr) {
            //Error while initializing the flows
            free_workflow(&workflow);
            return nullptr;
        }

        //Init the idle flows per thread
        workflow->total_idle_flows = 0;
        workflow->max_idle_flows = MAX_IDLE_FLOWS_PER_THREAD;
        workflow->ndpi_flows_idle = (void **) ndpi_calloc(workflow->max_idle_flows, sizeof(void *));
        if (workflow->ndpi_flows_idle == nullptr) {
            free_workflow(&workflow);
            return nullptr;
        }

        //Init the protocol bitmask
        NDPI_PROTOCOL_BITMASK protos;
        NDPI_BITMASK_SET_ALL(protos);
        ndpi_set_protocol_detection_bitmask2(workflow->ndpi_struct, &protos);
        ndpi_finalize_initalization(workflow->ndpi_struct);

        return workflow;
    }


    static void check_for_idle_flows(nDPI_workflow *const workflow)
    /*
     * Checks all the nodes, if they became idle from the last check or not
     * If yes, it frees them
     */
    {
        if (workflow->last_idle_scan_time + IDLE_SCAN_PERIOD < workflow->last_time) {
            for (size_t idle_scan_index = 0; idle_scan_index < workflow->max_active_flows; ++idle_scan_index) {
                ndpi_twalk(workflow->ndpi_flows_active[idle_scan_index], ndpi_idle_scan_walker, workflow);

                while (workflow->cur_idle_flows > 0) {
                    auto *const f =
                            (nDPI_flow_info *) workflow->ndpi_flows_idle[--workflow->cur_idle_flows];
                    if (f->flow_fin_ack_seen == 1) {
                        std::cout << "Free fin flow with id " << f->flow_id << "\n";
                    } else {
                        std::cout << "Free idle flow with id " << f->flow_id << "\n";
                    }
                    ndpi_tdelete(f, &workflow->ndpi_flows_active[idle_scan_index],
                                 nDPI_flow_info::ndpi_workflow_node_cmp);
                    nDPI_flow_info::ndpi_flow_info_freer(f);
                    workflow->cur_active_flows--;
                }
            }

            workflow->last_idle_scan_time = workflow->last_time;
        }
    }


    static void ndpi_idle_scan_walker(void const *const A, ndpi_VISIT which, int depth, void *const user_data)
    /*
     * Checks if "A" is an idle flow or not, in case it is, the function
     * adds the flow to the array of idle_flows
     * (nDPI_workflow user_data->ndpi_flows_idle[])
     */
    {
        auto *const workflow = (nDPI_workflow *) user_data;
        auto *const flow = *(nDPI_flow_info **) A;

        (void) depth;

        if (workflow == nullptr || flow == nullptr) {
            return;
        }

        if (workflow->cur_idle_flows == MAX_IDLE_FLOWS_PER_THREAD) {
            return;
        }

        if (which == ndpi_preorder || which == ndpi_leaf) {
            //Checks the last message time and compares it with the actual time
            if ((flow->flow_fin_ack_seen == 1 && flow->flow_ack_seen == 1) ||
                flow->last_seen + MAX_IDLE_TIME < workflow->last_time) {
                //If it surpasses the MAX_IDLE_TIME, consider the flow as an idle one
                char src_addr_str[INET6_ADDRSTRLEN + 1];
                char dst_addr_str[INET6_ADDRSTRLEN + 1];
                nDPI_flow_info::ip_tuple_to_string(flow, src_addr_str, sizeof(src_addr_str), dst_addr_str, sizeof(dst_addr_str));
                workflow->ndpi_flows_idle[workflow->cur_idle_flows++] = flow;
                workflow->total_idle_flows++;
            }
        }
    }
};