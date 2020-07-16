//
// Created by matteo on 09/07/2020.
//

#ifndef NDPILIGHT_READER_THREAD_H
#define NDPILIGHT_READER_THREAD_H

#include "ndpi_light_includes.h"
#include "reader.h"


class ReaderThread {
public:
    uint8_t reader_type = 1;    /* 1 for pcap, 0 for napatech   */
    Reader* rdr = nullptr;
    pthread_t thread_id = 0;

public:
    explicit ReaderThread();
};

static void process_helper(uint8_t * const args,
                           pcap_pkthdr const * const header,
                           uint8_t const * const packet)
{
    Reader * const reader_thread = (Reader *) args;
    reader_thread->processPacket(nullptr, header, packet);
};

#endif //NDPILIGHT_READER_THREAD_H
