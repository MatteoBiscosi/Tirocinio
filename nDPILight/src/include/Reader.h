#ifndef NDPILIGHT_READER_H
#define NDPILIGHT_READER_H

#include "ndpi_light_includes.h"



class Reader {
    protected:

        uint8_t error_or_eof;
        
        void **ndpi_flows_active;
        unsigned long long int max_active_flows;

        void **ndpi_flows_idle;
        unsigned long long int max_idle_flows;

        struct ndpi_detection_module_struct * ndpi_struct;

    public:
        Reader();
        ~Reader();

        virtual void printStats() = 0;
        virtual void newPacket(void * header) = 0;
        virtual int startRead() = 0;
        virtual int initFileOrDevice() = 0;
        virtual void stopRead() = 0;
        virtual int checkEnd() = 0;
        virtual int newFlow(FlowInfo * & flow_to_process) = 0;

        /* Getters and setters */
        uint8_t getErrorOfEof() { return this->error_or_eof; };

        void ** getActiveFlows() { return this->ndpi_flows_active; };
        void ** getIdleFlows() { return this->ndpi_flows_idle; };
        unsigned long long int getMaxActiveFlows() {return this->max_active_flows; };
        unsigned long long int getMaxIdleFlows() {return this->max_idle_flows; };

        struct ndpi_detection_module_struct * getNdpiStruct() { return this->ndpi_struct; };
};


/*  
 *  Function used to search for idle flows  
 */
void ndpi_idle_scan_walker(void const * const A, 
                            ndpi_VISIT which, 
                            int depth, 
                            void * const user_data);

/*  
 *  Checks if two nodes of the tree, A and B, are equals    
 */
int ndpi_workflow_node_cmp(void const * const A, 
                            void const * const B);                 


#endif //NDPILIGHT_READER_H
