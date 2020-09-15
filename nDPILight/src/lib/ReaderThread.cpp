#include "ndpi_light_includes.h"



/* ********************************** */

ReaderThread::ReaderThread() 
{
    this->thread_id = 0;
    this->rdr = nullptr;        
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

void ReaderThread::initReader(Reader *tmpRdr, int i, uint8_t thread_number) 
{
    this->type = 1; // Napatech 
    if(i == 0) {
    	NapatechReader *tmp = (NapatechReader *) tmpRdr;
	tmp->initConfig(thread_number);
    }
    this->rdr = tmpRdr;
    this->rdr->initFileOrDevice();
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

    this->rdr->~Reader();
}

/* ********************************** */
