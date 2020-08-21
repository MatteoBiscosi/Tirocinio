#ifndef NDPILIGHT_NAPATECH_READER_H
#define NDPILIGHT_NAPATECH_READER_H


#include "ndpi_light_includes.h"




extern PacketDissector * pkt_parser;
extern Trace * tracer;


class NapatechReader : public Reader {
    private:
        bool newFlowCheck;
        uint8_t adapterNo;
        NtFlowAttr_t flowAttr;

        NtNetStreamRx_t hNetRxAny;
        NtNetBuf_t hNetBufferAny;

        NtNetStreamRx_t hNetRxUnh;
        NtNetBuf_t hNetBufferUnh;

        NtConfigStream_t hCfgStream;

        NtFlowStream_t * flowStream;

        uint64_t last_idle_scan_time;
        uint64_t last_time;
        size_t idle_scan_index;
        size_t max_idle_scan_index;

        unsigned long long int idCounter;

        unsigned long long int last_packets_scan;    

        unsigned long long int cur_active_flows;
        unsigned long long int total_active_flows;
        
        unsigned long long int cur_idle_flows;
        unsigned long long int total_idle_flows;

    public:
        explicit NapatechReader();
        explicit NapatechReader(char const * dst);

        /*  
         *  Function used to start the pcap_loop   
         */
        int startRead() override;

        /*  
         *  Initializing the napatech_handler, 
         *  needed to read from a file or a device  
         */
        int initFileOrDevice() override;

        /*  
         *  Function used to set pcap to nullptr   
         */
        void stopRead() override;

        /*  
         *  Checks if eof is reached  
         */
        int checkEnd() override;

        /*  
         *  Prints infos about packets, flows and bytes  
         */
        void printStats() override;

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
        void incrTotalIdleFlows() { this->total_idle_flows++; };
        void incrCurIdleFlows() { this->cur_idle_flows++; };
        uint64_t getLastTime() { return this->last_time; };
        void **getNdpiFlowsIdle() { return this->ndpi_flows_idle; };    
        unsigned long long int getCurIdleFlows() { return this->cur_idle_flows; };
        unsigned long long int getTotalIdleFlows() { return this->cur_active_flows; };;
        void setNewFlow(bool flow) { newFlowCheck = flow; };
        bool getNewFlow() { return newFlowCheck; };
        NtNetStreamRx_t * getUnhStream() { return &hNetRxUnh; };
        NtNetBuf_t * getUnhBuffer() { return &hNetBufferUnh; };

    private:
        void checkForIdleFlows();

        int initInfos();
        int initModule();
        int initConfig(NtFlowAttr_t& flowAttr,
                        NtFlowStream_t& flowStream,
                        NtConfigStream_t& hCfgStream);
        int openStreams();
        
        void taskReceiverAny(const char* streamName, 
                    NtFlowStream_t& flowStream);

        int createNewFlow(NtFlowStream_t& flowStream);
};


#endif //NDPILIGHT_NAPATECH_READER_H
