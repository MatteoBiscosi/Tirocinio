#ifndef NDPILIGHT_READER_H
#define NDPILIGHT_READER_H

#include "ndpi_light_includes.h"


class Reader {
    protected:
        uint8_t error_or_eof;
        char *log_path;
        const char *type;
	    bool newFlowCheck;
	
        uint64_t last_idle_scan_time;
        uint64_t last_time;
        size_t idle_scan_index;
        size_t max_idle_scan_index;
        
        std::unordered_set<FlowInfo, KeyHasher> *ndpi_flows_active;

        unsigned long long int max_active_flows;
        unsigned long long int max_idle_flows;

        unsigned long long int cur_active_flows;
        unsigned long long int total_active_flows;
        
        unsigned long long int cur_idle_flows;
        unsigned long long int total_idle_flows;

        unsigned long long int last_packets_scan;

        unsigned long long int idFlow;

        struct ndpi_detection_module_struct * ndpi_struct;

        PROFILING_DECLARE(6);
    public:
	    Reader() {};
        Reader(char *log_path, const char *type);
        ~Reader();
       
         /**
          * Function used everytime a new flow is found
          * ()
          *
          * @return 1 if eof is reached or if the 
          *         analysis needs to be stopped, 0 otherwise
          *
          */
        int newFlow(FlowInfo * & flow_to_process);
        

        /**
         * Function used to print stats collected until now
         *
         */
        virtual void printStats() = 0;

        /**
         * Function called everytime a new packet is caught
         * (usally called to update counters and checking for
         * idle flows)
         *
         * @par    header = pointer the header of the packet
         * @return -1 in case of an error, 0 otherwise
         *
         */
        virtual void newPacket(void * header) = 0;

        /**
         * Function used to start reading from the file or
         * device specified with -i option
         *
         * @return -1 in case of an error, 0 otherwise
         *
         */
        virtual int startRead() = 0;

        /**
         * Function used to initialize the various devices
         * needed to start the capture
         *
         * @return -1 in case of an error, 0 otherwise
         *
         */
        virtual int initFileOrDevice() = 0;

        /**
         * Function called to stop reading from the file
         * or device
         *
         * @return -1 in case of an error, 0 otherwise
         *
         */
        virtual void stopRead() = 0;

        /**
         * Function used check if eof is reached or if the
         * analysis needs to be stopped
         *
         * @return 1 if eof is reached or if the 
         *         analysis needs to be stopped, 0 otherwise
         *
         */
        virtual int checkEnd() = 0;

        /**
         * Various getters and setters
         *
         */
        uint8_t getErrorOfEof() { return this->error_or_eof; };

        std::unordered_set<FlowInfo, KeyHasher> *getActiveFlows() { return this->ndpi_flows_active; };

        //void ** getIdleFlows() { return this->ndpi_flows_idle; };

        unsigned long long int getMaxActiveFlows() {return this->max_active_flows; };

        unsigned long long int getMaxIdleFlows() {return this->max_idle_flows; };

        struct ndpi_detection_module_struct * getNdpiStruct() { return this->ndpi_struct; };

        void incrTotalIdleFlows() { this->total_idle_flows++; };

        void incrCurIdleFlows() { this->cur_idle_flows++; };

        void incrTotalActiveFlows() { this->total_active_flows++; };

        void incrCurActiveFlows() { this->cur_active_flows++; };

        uint64_t getLastTime() { return this->last_time; };

        //void **getNdpiFlowsIdle() { return this->ndpi_flows_idle; }; 

        void setNewFlow(bool flow) { newFlowCheck = flow; };

        bool getNewFlow() { return newFlowCheck; };   

        unsigned long long int getCurIdleFlows() { return this->cur_idle_flows; };

        unsigned long long int getCurActiveFlows() { return this->cur_active_flows; };

        void setIdFlow(unsigned long long int idFlow) { this->idFlow = idFlow; };

        uint64_t getIdFlow() { return this->idFlow; };

        char * getPath() { return this->log_path; };

        const char * getType() { return this->type; };
};
              

#endif //NDPILIGHT_READER_H
