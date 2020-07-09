//
// Created by matteo on 09/07/2020.
//

#include <ndpi_light_includes.h>

ReaderThread::ReaderThread() : npt_rdr(nullptr), pcp_rdr(nullptr){}

ReaderThread::ReaderThread(NapatechReader rdr) {
    this->npt_rdr = rdr;
}

ReaderThread::ReaderThread(PcapReader rdr) {
    this->pcp_rdr = rdr;
}

