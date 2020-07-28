#ifndef NDPILIGHT_NAPATECH_READER_H
#define NDPILIGHT_NAPATECH_READER_H


#include "ndpi_light_includes.h"

class NapatechReader : public Reader {
public:
    const char *file_or_device = nullptr;

public:
    explicit NapatechReader();
    explicit NapatechReader(char const * dst);
};

#endif //NDPILIGHT_NAPATECH_READER_H
