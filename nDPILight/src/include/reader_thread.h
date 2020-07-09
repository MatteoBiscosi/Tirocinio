//
// Created by matteo on 09/07/2020.
//

#ifndef NDPILIGHT_READER_THREAD_H
#define NDPILIGHT_READER_THREAD_H


class ReaderThread {
public:
    NapatechReader npt_rdr;
    PcapReader pcp_rdr;
    pthread_t thread_id;
public:
    explicit ReaderThread();
    explicit ReaderThread(PcapReader rdr);
    explicit ReaderThread(NapatechReader rdr);
};

#endif //NDPILIGHT_READER_THREAD_H
