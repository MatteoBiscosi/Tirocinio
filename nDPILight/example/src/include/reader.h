//
// Created by matteo on 09/07/2020.
//

#ifndef NDPILIGHT_READER_H
#define NDPILIGHT_READER_H

#include "ndpi_light_includes.h"


class Reader {
public:

public:
    virtual int startRead() = 0;
    virtual void printInfos() = 0;
    virtual int initFileOrDevice() = 0;
    virtual void freeReader() = 0;
    virtual void stopRead() = 0;
    virtual int checkEnd() = 0;
    virtual void processPacket(uint8_t * args,
                               pcap_pkthdr const * header,
                               uint8_t const * packet) = 0;
};
#endif //NDPILIGHT_READER_H
