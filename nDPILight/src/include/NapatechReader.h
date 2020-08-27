#ifndef NDPILIGHT_NAPATECH_READER_H
#define NDPILIGHT_NAPATECH_READER_H


#include "ndpi_light_includes.h"




extern PacketDissector * pkt_parser;
extern Trace * tracer;


class NapatechReader : public Reader {
    private:
        uint8_t adapterNo;
        NtFlowAttr_t flowAttr;

        NtNetStreamRx_t hNetRxMiss;
        NtNetBuf_t hNetBufferMiss;

        NtNetStreamRx_t hNetRxUnh;
        NtNetBuf_t hNetBufferUnh;

        NtConfigStream_t hCfgStream;

        NtFlowStream_t * flowStream;

        NtStatistics_t hStat;
        NtStatStream_t hStatStream;

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

        NtStatStream_t getStat() { return this->hStatStream; };
    private:

        /**
         * Initialize various infos
         */
        int initInfos();

        /**
         * Initialize ndpi modules
         */
        int initModule();
        
        /**
         * Analyze each type of packet
         */
        void taskReceiverAny(const char* streamName, 
                    NtFlowStream_t& flowStream);
};


#endif //NDPILIGHT_NAPATECH_READER_H
