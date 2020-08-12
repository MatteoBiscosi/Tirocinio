#ifndef NDPILIGHT_PCAP_READER_H
#define NDPILIGHT_PCAP_READER_H

#include "ndpi_light_includes.h"



extern PacketDissector pkt_parser;
extern Trace *tracer;


class PcapReader : public Reader {
    public:

        const char *file_or_device;

    private:

        uint64_t last_idle_scan_time = 0;
        uint64_t last_time = 0;
        unsigned long long int last_packets_scan = 0;
        size_t idle_scan_index = 0;
        size_t max_idle_scan_index = 0;

        unsigned long long int cur_active_flows = 0;
        unsigned long long int total_active_flows = 0;

        
        unsigned long long int cur_idle_flows = 0;
        unsigned long long int total_idle_flows = 0;

        char pcap_error_buffer[PCAP_ERRBUF_SIZE];
        
    public:

        explicit PcapReader();
        explicit PcapReader(char const * dst);
        explicit PcapReader(char const * dst, int error_or_eof);

        ~PcapReader();

        /*  
         *  Prints infos about packets, flows and bytes  
         */
        void printStats() override;

        /*  
         *  Initializing the pcap_handler, 
         *  needed to read from a file or a device  
         */
        int initFileOrDevice() override;

        /*  
         *  Checks if eof is reached  
         */
        int checkEnd() override;

        /*  
         *  Function used to start the pcap_loop   
         */
        int startRead() override;

        /*  
         *  Function used to set pcap to nullptr   
         */
        void stopRead() override;

        /*  
         *  Function called each packet for updating infos  
         */
        void newPacket(void * header) override;

        /*  
         *  Function called each new flow, used to update
         *  flow's infos and allocate the necessary memory   
         */
        int newFlow(FlowInfo * & flow_to_process) override;


        /*      Getters and setters       */
        void incrTotalIdleFlows();

        void incrCurIdleFlows();

        uint64_t getLastTime();

        void **getNdpiFlowsIdle();
        
        unsigned long long int getCurIdleFlows();

        unsigned long long int getTotalIdleFlows();

    private:
        /*  
         *  Scan used to check if there are idle flows   
         */
        void checkForIdleFlows();

        /*  
         *  Initialize module's infos   
         */
        int initModule();

        /*  
         *  Initialize flow's infos   
         */
        int initInfos();
};


#endif //NDPILIGHT_PCAP_READER_H
