//
// Created by matteo on 09/07/2020.
//

#include "reader_thread.h"
#include "pcap_reader.h"


ReaderThread::ReaderThread() {
    this->reader_type = 0;
    this->rdr = nullptr;
    this->thread_id = 0;
    std::cout << "Reader thread constructor\n";
}

/* ********************************** */




