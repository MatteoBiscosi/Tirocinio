#ifndef NDPILIGHT_NAPATECH_READER_H
#define NDPILIGHT_NAPATECH_READER_H


#include "ndpi_light_includes.h"




extern PacketDissector * pkt_parser;
extern Trace * tracer;


class NapatechReader : public Reader {
    private:
        uint8_t adapterNo;
        NtFlowAttr_t flowAttr;

        NtNetStreamRx_t hNetRxAny;
        NtNetBuf_t hNetBufferAny;

        NtNetStreamRx_t hNetRxUnh;
        NtNetBuf_t hNetBufferUnh;

        NtConfigStream_t hCfgStream;

        NtFlowStream_t * flowStream;

        unsigned long long int idCounter;

    public:
	    ~NapatechReader();

       
        int startRead() override;

        int initFileOrDevice() override;

        void stopRead() override;

        int checkEnd() override;

        void printStats() override;

        void newPacket(void * header) override;
        
        
        /**  
         * Various getters and setter
         * 
         */
        NtNetStreamRx_t * getUnhStream() { return &hNetRxUnh; };
        
        NtNetBuf_t * getUnhBuffer() { return &hNetBufferUnh; };

    private:
        /**
         * Check if idle flows are present into this->ndpi_flows_active
         */
        void checkForIdleFlows();

        /**
         * Initialize various infos
         */
        int initInfos();

        /**
         * Initialize ndpi modules
         */
        int initModule();

        /**
         * Configure napatech library
         */
        int initConfig(NtFlowAttr_t& flowAttr,
                        NtFlowStream_t& flowStream,
                        NtConfigStream_t& hCfgStream);

        /**
         * Open streams configured in initConfig
         */
        int openStreams();
        
        /**
         * Analyze each type of packet
         */
        void taskReceiverAny(const char* streamName, 
                    NtFlowStream_t& flowStream);

        /**
         * Add a new flow to the nt_flow_table
         */
        int createNewFlow(NtFlowStream_t& flowStream);
};


#endif //NDPILIGHT_NAPATECH_READER_H
