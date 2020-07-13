//
// Created by matteo on 09/07/2020.
//

#ifndef NDPILIGHT_READER_THREAD_H
#define NDPILIGHT_READER_THREAD_H

#include <ndpi_light_includes.h>


class ReaderThread {
public:
    uint8_t reader_type;    /* 1 for pcap, 0 for napatech   */
    Reader* rdr;
    //NapatechReader npt_rdr;
    //PcapReader pcp_rdr;
    pthread_t thread_id;

public:
    explicit ReaderThread();
};

#endif //NDPILIGHT_READER_THREAD_H
