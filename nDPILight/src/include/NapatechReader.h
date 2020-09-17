#ifndef NDPILIGHT_NAPATECH_READER_H
#define NDPILIGHT_NAPATECH_READER_H


#include "ndpi_light_includes.h"




extern Trace * tracer;


class NapatechReader : public Reader {
    private:
	    PacketDissector *pkt_parser;

        uint8_t streamId;
        uint8_t adapterNo;
        NtFlowAttr_t flowAttr;

        NtNetStreamRx_t hNetRxMiss;
        NtNetBuf_t hNetBufferMiss;

        NtNetStreamRx_t hNetRxUnh;
        NtNetBuf_t hNetBufferUnh;

        NtConfigStream_t hCfgStream;

        NtFlowStream_t flowStream;

        NtStatistics_t hStat;
        NtStatStream_t hStatStream;

	    unsigned long long int init_pkts;
        unsigned long long int init_bytes;
    public:
        NapatechReader(char *log_path, const char *type, int streamId);
        ~NapatechReader();

        int initConfig(int stream_number);
       
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

        NtNetStreamRx_t * getMissStream() { return &hNetRxMiss; };
        
        NtNetBuf_t * getMissBuffer() { return &hNetBufferMiss; };

	    NtStatStream_t *getStatStream() { return &this->hStatStream; };

        NtFlowStream_t getFlowStream() { return this->flowStream; };

	void setFlowStream(NtFlowStream_t& flowStream) { this->flowStream = flowStream; };

        unsigned long long int getInitPkts() { return this->init_pkts; };

	    unsigned long long int getInitBytes() { return this->init_bytes; };

	uint8_t getStreamId() { return this->streamId; };

	PacketDissector *getParser() { return this->pkt_parser; };
	void setParser(PacketDissector *pkt_parser) { this->pkt_parser = pkt_parser; };
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
        //void taskReceiverAny(const char* streamName);
};


#endif //NDPILIGHT_NAPATECH_READER_H
