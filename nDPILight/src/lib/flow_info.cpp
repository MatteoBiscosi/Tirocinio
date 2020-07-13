//
// Created by matteo on 12/07/2020.
//
#include <ndpi_light_includes.h>


void FlowInfo::infoFreer()
{
    ndpi_free(this->ndpi_dst);
    ndpi_free(this->ndpi_src);
    ndpi_flow_free(this->ndpi_flow);
    ndpi_free(this);
}

/* ********************************** */
