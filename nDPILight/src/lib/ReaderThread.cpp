#include "ndpi_light_includes.h"



/* ********************************** */

ReaderThread::ReaderThread() 
{
    this->rdr = nullptr;
    this->thread_id = 0;
}

/* ********************************** */

ReaderThread::~ReaderThread()
{
    if(this->rdr != nullptr)
    	delete(this->rdr);
}

/* ********************************** */

void ReaderThread::initReader(Reader* tmpRdr) 
{
    this->rdr = tmpRdr;
}

/* ********************************** */

int ReaderThread::init()
{
    if(this->rdr->initFileOrDevice() != 0)
        return 1;
    
    return 0;
}

/* ********************************** */

void ReaderThread::startRead()
{
    this->rdr->startRead();
}

/* ********************************** */

void ReaderThread::stopRead()
{
    this->rdr->stopRead();
}

/* ********************************** */

void ReaderThread::printStats()
{
    this->rdr->printStats();
}

/* ********************************** */

void ReaderThread::close()
{
    if(this->rdr != nullptr)
        delete(this->rdr);
}

/* ********************************** */
