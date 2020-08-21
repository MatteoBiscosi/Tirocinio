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

ReaderThread::~ReaderThread()
{
    if(this->rdr != nullptr)
    	delete(this->rdr);
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

int ReaderThread::init()
{
    if(this->rdr->initFileOrDevice() != 0)
        return 1;
    
    return 0;
}

void ReaderThread::startRead()
{
    this->rdr->startRead();
}

void ReaderThread::stopRead()
{
    this->rdr->stopRead();
}

void ReaderThread::printStats()
{
    this->rdr->printStats();
}

void ReaderThread::close()
{
    if(this->rdr != nullptr)
        delete(this->rdr);
}
/*
void ReaderThread::forceClose()
{
    pcap_close(this->rdr->pcap_handle);
}*/
/* ********************************** */

