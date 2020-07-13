//
// Created by matteo on 09/07/2020.
//

#ifndef NDPILIGHT_READER_H
#define NDPILIGHT_READER_H

#include <ndpi_light_includes.h>


class Reader {
public:

public:
    virtual int start_read() = 0;
    virtual void printInfos() = 0;
    virtual int initFileOrDevice() = 0;
    virtual void freeReader() = 0;
    virtual void stop_read() = 0;
    virtual int check_end() = 0;
};
#endif //NDPILIGHT_READER_H
