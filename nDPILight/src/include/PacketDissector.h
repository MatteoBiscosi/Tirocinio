#ifndef NDPILIGHT_PACKET_DISSECTOR_H
#define NDPILIGHT_PACKET_DISSECTOR_H


#include "ndpi_light_includes.h"


extern uint32_t mask;
extern int generate_logs;

class PacketDissector {
    protected:
	bool newFlow;
	uint64_t flowId;
        uint64_t flow_id;
	char *log_path;
	const char *if_type;

        std::queue<std::string> allarm_list;

        ndpi_serializer serializer;
        ndpi_serialization_format fmt;
        
        class CaptureStats {
            public:
                unsigned long long int unhandled_packets;
                unsigned long long int packets_captured;
                unsigned long long int previous_packets;
                unsigned long long int discarded_bytes;
                unsigned long long int ip_pkts;
                unsigned long long int ip_bytes;
                unsigned long long int tcp_pkts;
                unsigned long long int udp_pkts;
                
                unsigned long long int total_flows_captured;

                time_t time_start, time_end; 

                unsigned long long int packets_processed;
                unsigned long long int total_l4_data_len;
                unsigned long long int total_wire_bytes;

                unsigned long long int detected_flow_protocols;
                unsigned long long int guessed_flow_protocols;
                unsigned long long int unclassified_flow_protocols;

                uint16_t* protos_cnt;
        } captured_stats; 

	PROFILING_DECLARE(5);

    private:

        /**
         * Function used to add flow to the hashtable 
         * (reader->ndpi_flows_active)
         *
         */ 
	    int addVal(Reader * & reader,
                    FlowInfo & flow,
                    PacketInfo & pkt_infos);

    protected:
        /**
         * Function used to search inside an hashtable
         * if flow is already inside it.
         * 
         * @par    reader    = pointer to Reader
         * @par    flow      = FlowInfo to search
         * @par    pkt_infos = infos about the packet from 
         *                     which flow is extracted
         * @return 0 if flow is found, -1 otherwise
         *
         */  
	    int searchVal(Reader * & reader,
                      FlowInfo& flow,
                      PacketInfo & pkt_infos);

    public:
        PacketDissector(const char *type);
        PacketDissector(const char *type,
			uint num);
	PacketDissector(char *log_path, 
			const char *type);
        ~PacketDissector();

	/**
         * Print packets and bytes received
         * 
         */
        virtual void printBriefInfos(Reader *reader) = 0;


        /**
         * Function used to parse a packet, called
         * each packet
         * 
         * @par    flow       = FlowInfo in which store infos
         * @par    args       = pointer to Reader
         * @par    header_tmp = pointer to the header
         * @par    packet_tmp = pointer to the packet
         * @par    pkt_infos  = storage of infos about the packet
         * @return -1 in case of error, 0 in case of flow surely not 
         *         inside the hashtable, 1 in case flow search isnt 
         *         done (and need to be done inside process packet)
         *         2 in case flow is found inside the hashtable
         *
         */ 
        virtual int parsePacket(FlowInfo & flow,
                                Reader * &args,
                                void * header_tmp,
                                void * packet_tmp,
                                PacketInfo & pkt_infos) = 0;

        /**
         * This function is called every time a new packets appears;
         * it process all the packets, adding new flows, updating 
         * infos, ecc.  
         * 
         * @par    args   = pointer to Reader
         * @par    header = pointer to the header of the packet
         * @par    packet = pointer to the packet
         *
         */ 
        void processPacket(void * args,
                            void * header,
                            void * packet);

        /**
         * Function used to initialize the pointer used for ids
         *
         * @par    num = number of the protocols
         * 
         */  
        void initProtosCnt(uint num);

        /**
         * Function used to print stats collected until now
         *
         * @par    reader = pointer to a Reader
         * 
         */  
        void printStats(Reader* reader);

        /**
         * Function used to print stats of a 
         *
         * @par    reader    = pointer to a Reader
         * @par    pkt_infos = pointer to a FlowInfo
         * 
         */
        void printFlow(Reader* reader, 
                        FlowInfo * pkt_infos);

        /**
         * Function used to save flow's infos on a JSON file 
         *
         * @par    reader    	       = pointer to a Reader
         * @par    pkt_infos 	       = pointer to a FlowInfo
         * @par	   guessed_or_detected = 0 if the protocol is guessed
         * 				 1 if the protocol is detected
         * @return -1 in case of error, 0 otherwise
         *
         */
        int flowToJson(Reader* reader,
                        FlowInfo* flow_infos,
			int guessed_or_detected);

        /**
         * Various setters and getters
         * 
         */ 
	unsigned long long int getPktsCaptured() { return captured_stats.packets_captured; };
        unsigned long long int getUnhPkts() { return captured_stats.unhandled_packets; };
	unsigned long long int getDiscardedBytes() { return captured_stats.discarded_bytes; };
	unsigned long long int getIpPkts() { return captured_stats.ip_pkts; };
	unsigned long long int getIpBytes() { return captured_stats.ip_bytes; };
	unsigned long long int getTcpPkts() { return captured_stats.tcp_pkts; };
	unsigned long long int getUdpPkts() { return captured_stats.udp_pkts; };
	unsigned long long int getCptFlows() { return captured_stats.total_flows_captured; };
	unsigned long long int getProcPkts() { return captured_stats.packets_processed; };
	unsigned long long int getL4Bytes() { return captured_stats.total_l4_data_len; };
	unsigned long long int getTotBytes() { return captured_stats.total_wire_bytes; };
        const time_t getStartAnalysis() { return captured_stats.time_start; };
        const time_t getEndAnalysis() { return captured_stats.time_end; };
	unsigned long long int getDetectedProtos() { return captured_stats.detected_flow_protocols; };
	unsigned long long int getGuessedProtos() { return captured_stats.guessed_flow_protocols; };
	unsigned long long int getUnclassProtos() { return captured_stats.unclassified_flow_protocols; };
	uint16_t * getProtosCnt() { return captured_stats.protos_cnt; };

        void setStartAnalysis() { struct timeval actual_time; gettimeofday(&actual_time, nullptr); this->captured_stats.time_start = actual_time.tv_sec; };
        void setEndAnalysis() { struct timeval actual_time; gettimeofday(&actual_time, nullptr); this->captured_stats.time_end = actual_time.tv_sec; };
	void incrPktsCaptured() { this->captured_stats.packets_captured++; };
        void incrUnhaPkts() { this->captured_stats.unhandled_packets++; };
	void incrWireBytes(unsigned long long int bytes) { this->captured_stats.total_wire_bytes += bytes; };
        std::queue<std::string> *getAllarmList() { return &this->allarm_list; };
	const char *getType() { return this->if_type; };
	char *getLogPath() { return this->log_path; };
        bool newFlowCheck() { return this->newFlow; };
        void setNewFlow(bool flow) { this->newFlow = flow; };
	uint64_t getFlowId() { return this->flowId; };
};


#endif
