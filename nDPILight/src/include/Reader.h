#ifndef NDPILIGHT_READER_H
#define NDPILIGHT_READER_H

#include "ndpi_light_includes.h"



class Reader {
    public:

        uint8_t error_or_eof = 0;

        pcap_t *pcap_handle = nullptr;
        
        void **ndpi_flows_active = nullptr;
        unsigned long long int max_active_flows = 0;

        void **ndpi_flows_idle = nullptr;
        unsigned long long int max_idle_flows = 0;

        struct ndpi_detection_module_struct * ndpi_struct = nullptr;

    public:

        virtual ~Reader() {};

        virtual void printStats() = 0;
        virtual void newPacket(pcap_pkthdr const * const header) = 0;
        virtual int startRead() = 0;
        virtual int initFileOrDevice() = 0;
        virtual void stopRead() = 0;
        virtual int checkEnd() = 0;
        virtual int newFlow(FlowInfo * & flow_to_process) = 0;
};


/*  
 *  Function used to search for idle flows  
 */
void ndpi_idle_scan_walker(void const * const A, 
                            ndpi_VISIT which, 
                            int depth, 
                            void * const user_data);

/*  
 *  Checks if two nodes of the tree, A and B, are equals    
 */
int ndpi_workflow_node_cmp(void const * const A, 
                            void const * const B);                 


#endif //NDPILIGHT_READER_H
