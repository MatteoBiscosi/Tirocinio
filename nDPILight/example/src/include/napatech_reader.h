//
// Created by matteo on 09/07/2020.
//

#ifndef NDPILIGHT_NAPATECH_READER_H
#define NDPILIGHT_NAPATECH_READER_H


#include "ndpi_light_includes.h"
#include "reader.h"

class NapatechReader : public Reader {
public:
    const char *file_or_device = nullptr;

public:
    explicit NapatechReader();
    explicit NapatechReader(char const * dst);
    int prova();
};

#endif //NDPILIGHT_NAPATECH_READER_H
