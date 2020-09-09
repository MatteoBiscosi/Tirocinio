#ifndef NDPILIGHT_PCAP_READER_H
#define NDPILIGHT_PCAP_READER_H

#include "ndpi_light_includes.h"



extern Trace *tracer;


class PcapReader : public Reader {
    public:
        const char *file_or_device;

    private:
        pcap_t *pcap_handle;
	PacketDissector *pkt_parser;

        char pcap_error_buffer[PCAP_ERRBUF_SIZE];
        
    public:
        explicit PcapReader(char *log_path, const char *type);
        explicit PcapReader(char *log_path, const char *type, const char * dst);
        explicit PcapReader(char *log_path, const char *type, const char * dst, int error_or_eof);

        ~PcapReader();


        void printStats() override;

        int initFileOrDevice() override;

        int checkEnd() override;

        int startRead() override;

        void stopRead() override;

        void newPacket(void * header) override;


        /**
         * Getters and setters
         * 
         */
        void incrTotalIdleFlows();

        void incrCurIdleFlows();

        uint64_t getLastTime();

        void **getNdpiFlowsIdle();
        
        unsigned long long int getCurIdleFlows();

        unsigned long long int getTotalIdleFlows();

        pcap_t* getPcapHandle() { return this->pcap_handle; };

	PacketDissector *getParser() { return this->pkt_parser; };

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
