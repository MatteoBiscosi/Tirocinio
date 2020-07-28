#ifndef NDPILIGHT_READER_THREAD_H
#define NDPILIGHT_READER_THREAD_H

#include "ndpi_light_includes.h"


class ReaderThread {
    public:

        uint8_t reader_type = 1;    /* 1 for pcap, 0 for napatech   */
        Reader* rdr = nullptr;
        pthread_t thread_id = 0;

    public:

        explicit ReaderThread();
};


#endif //NDPILIGHT_READER_THREAD_H
