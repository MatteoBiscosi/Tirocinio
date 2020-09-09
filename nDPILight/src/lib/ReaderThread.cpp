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
    this->type = 0; // Pcap
    this->rdr = tmpRdr;
}

/* ********************************** */

void ReaderThread::initReader(Reader* tmpRdr, int i, int thread_number) 
{
    this->type = 1; // Napatech
    this->thread_number = thread_number;
    if(i == 0) {
        this->rdr = (Reader *) new NapatechReader[thread_number];
    }

    this->rdr[i] = *tmpRdr;
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
    if(this->type == 1) {
        for(int i = 0; i < this->thread_number; i++)
            this->rdr[i].startRead();
    }
    else
    {
        this->rdr->startRead();
    }
    
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
