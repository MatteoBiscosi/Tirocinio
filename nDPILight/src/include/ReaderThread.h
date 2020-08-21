#ifndef NDPILIGHT_READER_THREAD_H
#define NDPILIGHT_READER_THREAD_H

#include "ndpi_light_includes.h"


class ReaderThread {
    private:
        uint8_t reader_type;    /* 1 for pcap, 0 for napatech   */
        Reader* rdr;
        pthread_t thread_id;

    public:
        explicit ReaderThread();
        ~ReaderThread();

        void initNtReader(Reader* tmpRdr);
        void initPcapReader(Reader* tmpRdr);

        int init();
        void startRead();
        void stopRead();
        void printStats();

        void setThreadId(pthread_t tmp_thread_id) { this->thread_id = tmp_thread_id; };
        pthread_t* getThreadIdPtr() { return &this->thread_id; };
        pthread_t getThreadId() { return this->thread_id; };
        uint8_t getEof() { return this->rdr->getErrorOfEof(); };
};


#endif //NDPILIGHT_READER_THREAD_H
