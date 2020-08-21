//
// Created by matteo on 09/07/2020.
//

#include "ndpi_light_includes.h"


ReaderThread::ReaderThread() 
{
    this->reader_type = 0;
    this->rdr = nullptr;
    this->thread_id = 0;
}

void ReaderThread::initNtReader(Reader* tmpRdr) 
{
    this->rdr = tmpRdr;
    this->reader_type = 0;
}

void ReaderThread::initPcapReader(Reader* tmpRdr) 
{
    this->rdr = tmpRdr;
    this->reader_type = 1;
}

/* ********************************** */

