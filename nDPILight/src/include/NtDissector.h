#ifndef NDPILIGHT_NT_DISSECTOR_H
#define NDPILIGHT_NT_DISSECTOR_H


#include "ndpi_light_includes.h"


class NtDissector {


    private:
        NtDyn1Descr_t* pDyn1;
        uint8_t* packet;
    
};

#endif