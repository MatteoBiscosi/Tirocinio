#ifndef NDPILIGHT_READER_THREAD_H
#define NDPILIGHT_READER_THREAD_H

#include "ndpi_light_includes.h"


class ReaderThread {
    private:
        int type;
        Reader* rdr;
        pthread_t thread_id;

    public:
        explicit ReaderThread();
        ~ReaderThread();

        /**
         * Function used to set this->rdr to tmpRdr
         * 
         * @par    tmpRdr = pointer to a Reader
         * 
         */
        void initReader(Reader* tmpRdr);

        /**
         * Function used to set this->rdr to tmpRdr
         * 
         * @par    tmpRdr = pointer to a Reader
         * @par    i      = number of Reader to setup 
         * @par    thread_number = number of readers
         * 
         */
        void initReader(Reader *tmpRdr, int i, uint8_t thread_number);

        /**
         * Function used to start the initialization,
         * calling this->rdr->initFileOrDevice()
         * 
         * @return 1 in case of error, 0 otherwise
         * 
         */
        int init();

        /**
         * Function used to start reading from the
         * file or device
         * 
         */
        void startRead();

        /**
         * Function used to stop reading from the
         * file or device
         * 
         */
        void stopRead();

        /**
         * Function used to start print stats collected
         * until now
         * 
         */
        void printStats();

        /**
         * Function used to forcibly close this, 
         * by deleting it
         * 
         */
	    void close();

        /**
         * Various getters and setters
         *
         */
        void setThreadId(pthread_t tmp_thread_id) { this->thread_id = tmp_thread_id; };

	    void setType(uint8_t type) { this->type = type; };

        pthread_t* getThreadIdPtr() { return &this->thread_id; };

        pthread_t getThreadId() { return this->thread_id; };

        uint8_t getEof() { if(this->rdr != nullptr) return this->rdr->getErrorOfEof(); return 1; };

        Reader* getReader() { return this->rdr; };
};


#endif //NDPILIGHT_READER_THREAD_H
