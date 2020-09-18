#include "ndpi_light_includes.h"


std::mutex mtx;

void allarmManager(PacketDissector * pkt_dissector)
{
    char theDate[40];
    Trace* trace_allarm = new Trace();
    struct tm *timenow;
    time_t now = time(NULL);
    timenow = gmtime(&now);

    if(pkt_dissector->getLogPath() == nullptr) {
    	strftime(theDate, sizeof(theDate), "_%Y-%m-%d_%H:%M:%S", timenow);
	char log_path[40] = "logs/";
	strcat(log_path, pkt_dissector->getType());
	strcat(log_path, theDate);
        strcpy(theDate, log_path); 
    }
    else {
	strftime(theDate, sizeof(theDate), "_%Y-%m-%d_%H:%M:%S", timenow);
	char *log_path = (char *)pkt_dissector->getLogPath();
	printf("%s, %s, %s\n", log_path, theDate);
	strcat(log_path, theDate);
	strcpy(theDate, log_path);
	printf("%s, %s, %s\n", log_path, theDate);
    }
    
    std::ofstream outfile (theDate);
    trace_allarm->set_log_file(theDate);
    std::queue<std::string> *list = pkt_dissector->getAllarmList();

    while(true) {
        sleep(10);
	
		while(!list->empty()) {
			if(trace_allarm->getNumLines() >= 20000) {
				timenow = gmtime(&now);

				if(pkt_dissector->getLogPath() == nullptr) {
						strftime(theDate, sizeof(theDate), "_%Y-%m-%d_%H:%M:%S", timenow);
						char log_path[40] = "logs/";
						strcat(log_path, pkt_dissector->getType());
						strcat(log_path, theDate);
						strcpy(theDate, log_path);
				}
					else {
						strftime(theDate, sizeof(theDate), "_%Y-%m-%d_%H:%M:%S", timenow);
						char *log_path = (char *) pkt_dissector->getLogPath();
					strcat(log_path, pkt_dissector->getType());
						strcat(log_path, theDate);
						strcpy(theDate, log_path);
					}
					std::ofstream outfile (theDate);
					trace_allarm->set_log_file(theDate);
			}
			mtx.lock();
			trace_allarm->traceAllarm((list->front()).c_str());
			list->pop();
			mtx.unlock();
		}
    } 

	trace_allarm->~Trace();
}


PacketDissector::PacketDissector(const char *type)
{
	this->log_path = nullptr;
	this->if_type = type;
	this->captured_stats.protos_cnt = nullptr;
	ndpi_init_serializer(&this->serializer, this->fmt = ndpi_serialization_format_json);
	std::thread allarmThread(allarmManager, this);
	allarmThread.detach();

	this->captured_stats.unhandled_packets = 0;
	this->captured_stats.packets_captured = 0;
	this->captured_stats.previous_packets = 0;
	this->captured_stats.discarded_bytes = 0;
	this->captured_stats.ip_pkts = 0;
	this->captured_stats.ip_bytes = 0;
	this->captured_stats.tcp_pkts = 0;
	this->captured_stats.udp_pkts = 0;
	
	this->captured_stats.total_flows_captured = 0;

	this->captured_stats.time_start = 0;
	this->captured_stats.time_end = 0; 

	this->captured_stats.packets_processed = 0;
	this->captured_stats.total_l4_data_len = 0;
	this->captured_stats.total_wire_bytes = 0;

	this->captured_stats.detected_flow_protocols = 0;
	this->captured_stats.guessed_flow_protocols = 0;
	this->captured_stats.unclassified_flow_protocols = 0;
}

/* ********************************** */

PacketDissector::PacketDissector(const char *type, uint num)
{
	this->log_path = nullptr;
	this->if_type = type;
	this->captured_stats.protos_cnt = new uint16_t[num + 1] ();
	ndpi_init_serializer(&this->serializer, this->fmt = ndpi_serialization_format_json);
	std::thread allarmThread(allarmManager, this);
	allarmThread.detach();

	this->captured_stats.unhandled_packets = 0;
	this->captured_stats.packets_captured = 0;
	this->captured_stats.previous_packets = 0;
	this->captured_stats.discarded_bytes = 0;
	this->captured_stats.ip_pkts = 0;
	this->captured_stats.ip_bytes = 0;
	this->captured_stats.tcp_pkts = 0;
	this->captured_stats.udp_pkts = 0;

	this->captured_stats.total_flows_captured = 0;

	this->captured_stats.time_start = 0;
	this->captured_stats.time_end = 0;

	this->captured_stats.packets_processed = 0;
	this->captured_stats.total_l4_data_len = 0;
	this->captured_stats.total_wire_bytes = 0;

	this->captured_stats.detected_flow_protocols = 0;
	this->captured_stats.guessed_flow_protocols = 0; 
	this->captured_stats.unclassified_flow_protocols = 0;
}

/* ********************************** */

PacketDissector::PacketDissector(char *log_path, const char *type)
{
	this->log_path = log_path;
	this->if_type = type;
	this->captured_stats.protos_cnt = nullptr;
	ndpi_init_serializer(&this->serializer, this->fmt = ndpi_serialization_format_json);
	std::thread allarmThread(allarmManager, this);
	allarmThread.detach();

	this->captured_stats.unhandled_packets = 0;
	this->captured_stats.packets_captured = 0;
	this->captured_stats.previous_packets = 0;
	this->captured_stats.discarded_bytes = 0;
	this->captured_stats.ip_pkts = 0;
	this->captured_stats.ip_bytes = 0;
	this->captured_stats.tcp_pkts = 0;
	this->captured_stats.udp_pkts = 0;

	this->captured_stats.total_flows_captured = 0;

	this->captured_stats.time_start = 0;
	this->captured_stats.time_end = 0;

	this->captured_stats.packets_processed = 0;
	this->captured_stats.total_l4_data_len = 0;
	this->captured_stats.total_wire_bytes = 0;

	this->captured_stats.detected_flow_protocols = 0;
	this->captured_stats.guessed_flow_protocols = 0; 
	this->captured_stats.unclassified_flow_protocols = 0;
}

/* ********************************** */

PacketDissector::~PacketDissector()
{
	if(this == nullptr)
		return;

	if(this->captured_stats.protos_cnt != nullptr)
		delete [] this->captured_stats.protos_cnt;

	ndpi_term_serializer(&this->serializer);
}

/* ********************************** */

void PacketDissector::initProtosCnt(uint num)
{
	this->captured_stats.protos_cnt = new uint16_t[num + 1] ();
}

/* ********************************** */

void PacketDissector::printFlow(Reader* reader, 
		FlowInfo * pkt_infos)
{
	char src_addr_str[INET6_ADDRSTRLEN+1];
	char dst_addr_str[INET6_ADDRSTRLEN+1];

	pkt_infos->ipTupleToString(src_addr_str, sizeof(src_addr_str), dst_addr_str, sizeof(dst_addr_str));

	tracer->traceEvent(2, "\tFlow Summary:\r\n");
	tracer->traceEvent(2, "\t\tFlow id: %lu | Packets received: %lu | Bytes received: %lu | Src ip: %s | Src port %d | Dst ip: %s | Dst port %d\r\n", 
			pkt_infos->flow_id, pkt_infos->packets_processed, pkt_infos->bytes_processed, 
			src_addr_str, pkt_infos->src_port, dst_addr_str, pkt_infos->dst_port);
}

/* ********************************** */

int PacketDissector::flowToJson(Reader* reader,
		FlowInfo* flow_infos,
		int guessed_or_detected)
{
	char src_addr_str[INET6_ADDRSTRLEN+1];
	char dst_addr_str[INET6_ADDRSTRLEN+1];
	ndpi_serializer serializer;
	ndpi_serialization_format fmt;
	ndpi_init_serializer(&serializer, fmt = ndpi_serialization_format_json);
	flow_infos->ipTupleToString(src_addr_str, sizeof(src_addr_str), dst_addr_str, sizeof(dst_addr_str));

	ndpi_serialize_string_string(&serializer, "src_ip", src_addr_str);
	ndpi_serialize_string_string(&serializer, "dest_ip", dst_addr_str);
	ndpi_serialize_string_uint32(&serializer, "src_port", flow_infos->src_port);
	ndpi_serialize_string_uint32(&serializer, "dst_port", flow_infos->dst_port);

	switch(flow_infos->l4_protocol) {
		case IPPROTO_TCP:
			ndpi_serialize_string_string(&serializer, "proto", "TCP");
			break;

		case IPPROTO_UDP:
			ndpi_serialize_string_string(&serializer, "proto", "UDP");
			break;

		case IPPROTO_ICMP:
			ndpi_serialize_string_string(&serializer, "proto", "ICMP");
			break;

		default:
			ndpi_serialize_string_uint32(&serializer, "proto", flow_infos->l4_protocol);
			break;
	}

	switch(guessed_or_detected) {
		case 0:
			if(ndpi_dpi2json(reader->getNdpiStruct(), flow_infos->ndpi_flow, flow_infos->guessed_protocol, &serializer) != 0)
				return -1;

		case 1:
			if(ndpi_dpi2json(reader->getNdpiStruct(), flow_infos->ndpi_flow, flow_infos->detected_l7_protocol, &serializer) != 0)
				return -1;
	}

	uint32_t buffer_len = 0;
	std::string newAllarm = ndpi_serializer_get_buffer(&serializer, &buffer_len);
	mtx.lock();
	this->allarm_list.push(newAllarm);
	mtx.unlock();
	ndpi_term_serializer(&serializer);
	return 0;
}

/* ********************************** */

void PacketDissector::printStats(Reader *reader)
{
	long long unsigned int avg_pkt_size = 0;
	long long unsigned int breed_stats[NUM_BREEDS] = { 0 };
	char buf[32], when[64];
	struct tm result;
	

	tracer->traceEvent(2, "\tTraffic statistics:\r\n");
	tracer->traceEvent(2, "\t\tEthernet bytes:             %-20llu (includes ethernet CRC/IFC/trailer)\n",
			this->captured_stats.total_wire_bytes);
	tracer->traceEvent(2, "\t\tDiscarded bytes:            %-20llu\n",
			this->captured_stats.discarded_bytes);
	tracer->traceEvent(2, "\t\tIP packets:                 %-20llu of %llu packets total\n",
			this->captured_stats.ip_pkts,
			this->captured_stats.packets_captured);
	tracer->traceEvent(2, "\t\tUnhandled IP packets:       %-20llu\n",
			this->captured_stats.unhandled_packets);
	/* In order to prevent Floating point exception in case of no traffic*/
	if(this->captured_stats.ip_pkts != 0)
		avg_pkt_size = this->captured_stats.ip_bytes/this->captured_stats.ip_pkts;

	tracer->traceEvent(2, "\t\tIP bytes:                   %-20llu (avg pkt size %u bytes)\n",
			this->captured_stats.ip_bytes, avg_pkt_size);

	tracer->traceEvent(2, "\t\tUnique flows:               %-20u\n", this->captured_stats.total_flows_captured);

	tracer->traceEvent(2, "\t\tTCP Packets:                %-20lu\n", this->captured_stats.tcp_pkts);
	tracer->traceEvent(2, "\t\tUDP Packets:                %-20lu\n", this->captured_stats.udp_pkts);

	strftime(when, sizeof(when), "%d/%b/%Y %H:%M:%S", localtime_r(&this->captured_stats.time_start, &result));
	tracer->traceEvent(2, "\t\tAnalysis begin:             %-20s\n", when);
	strftime(when, sizeof(when), "%d/%b/%Y %H:%M:%S", localtime_r(&this->captured_stats.time_end, &result));
	tracer->traceEvent(2, "\t\tAnalysis end:               %-20s\n", when);

	tracer->traceEvent(2, "\t\tDetected flow protos:       %-20u\n", this->captured_stats.detected_flow_protocols);
	tracer->traceEvent(2, "\t\tGuessed flow protos:        %-20u\n", this->captured_stats.guessed_flow_protocols);
	tracer->traceEvent(2, "\t\tUnclassified flow protos:   %-20u\r\n", this->captured_stats.unclassified_flow_protocols);


	tracer->traceEvent(2, "\tDetected protocols:\r\n");

	for(u_int32_t i = 0; i <= ndpi_get_num_supported_protocols(reader->getNdpiStruct()); i++) {
		ndpi_protocol_breed_t breed = ndpi_get_proto_breed((reader->getNdpiStruct()), i);
		if(this->captured_stats.protos_cnt[i] > 0) {
			breed_stats[i] += this->captured_stats.protos_cnt[i];

			tracer->traceEvent(2, "\t\t%-20s flows: %-13u\r\n",
					ndpi_get_proto_name((reader->getNdpiStruct()), i), this->captured_stats.protos_cnt[i]);
		}
	}
	
	tracer->traceEvent(2, "\tProtocol statistics:\n");

	for(u_int32_t i = 0; i < NUM_BREEDS; i++) {
	   if(breed_stats[i] > 0) {
			tracer->traceEvent(2, "\t\t%-20s flows: %-13u\n",
	   		ndpi_get_proto_breed_name(reader->getNdpiStruct(), ndpi_get_proto_breed(reader->getNdpiStruct(), i)),
	    	breed_stats[i]);
	   }
	}
}

/* ********************************** */

int PacketDissector::searchVal(Reader * & reader,
		FlowInfo& flow,
		PacketInfo & pkt_infos)
{return 0;}

/* ********************************** */

int PacketDissector::addVal(Reader * & reader,
		FlowInfo & flow,
		PacketInfo & pkt_infos)
{return 0;}

/* ********************************** */

void PacketDissector::processPacket(void * const args,
		void * header_tmp,
		void * packet_tmp)
{
	KeyInfo key = KeyInfo();
	FlowInfo flow = FlowInfo();
	Reader * reader = (Reader *) args;
	PacketInfo pkt_infos = PacketInfo();

	/* Parsing the packet */
	this->captured_stats.packets_captured++;

	if(this->parsePacket(key, flow, reader, header_tmp, packet_tmp, pkt_infos) == -1)	
		return;
		
	if(pkt_infos.tree_result == reader->getActiveFlows()->end()) {

		/* Adding new flow to the hashtable */
		if (reader->getCurActiveFlows() == reader->getMaxActiveFlows()) {
        	tracer->traceEvent(0, "[10] max flows to track reached: %llu, idle: %llu\n",
                                	reader->getMaxActiveFlows(), reader->getCurIdleFlows());
			this->captured_stats.discarded_bytes += pkt_infos.ip_offset + pkt_infos.eth_offset;
        		return;
    		}

    		pkt_infos.flow_to_process = new FlowInfo();
    		if (pkt_infos.flow_to_process == nullptr) {
        		tracer->traceEvent(0, "[10] Not enough memory for flow info\n");
			this->captured_stats.discarded_bytes += pkt_infos.ip_offset + pkt_infos.eth_offset;
        		return;
    		}

    		reader->incrCurActiveFlows();
    		reader->incrTotalActiveFlows();

		memcpy(pkt_infos.flow_to_process, &flow, sizeof(*pkt_infos.flow_to_process));
		pkt_infos.flow_to_process->flow_id = flow_id++;

		pkt_infos.flow_to_process->ndpi_flow = (struct ndpi_flow_struct *)ndpi_flow_malloc(SIZEOF_FLOW_STRUCT);
		if (pkt_infos.flow_to_process->ndpi_flow == nullptr) {
			tracer->traceEvent(0, "[%8llu, %4u] Not enough memory for flow struct\n",
					this->captured_stats.packets_captured, pkt_infos.flow_to_process->flow_id);
			this->captured_stats.discarded_bytes += pkt_infos.ip_offset + pkt_infos.eth_offset;
			return;
		}

		memset(pkt_infos.flow_to_process->ndpi_flow, 0, SIZEOF_FLOW_STRUCT);

		pkt_infos.flow_to_process->ndpi_src = (struct ndpi_id_struct *)ndpi_calloc(1, SIZEOF_ID_STRUCT);
		if (pkt_infos.flow_to_process->ndpi_src == nullptr) {
			tracer->traceEvent(0, "[%8llu, %4u] Not enough memory for src id struct\n",
					this->captured_stats.packets_captured, pkt_infos.flow_to_process->flow_id);
			this->captured_stats.discarded_bytes += pkt_infos.ip_offset + pkt_infos.eth_offset;
			return;
		}

		pkt_infos.flow_to_process->ndpi_dst = (struct ndpi_id_struct *)ndpi_calloc(1, SIZEOF_ID_STRUCT);
		if (pkt_infos.flow_to_process->ndpi_dst == nullptr) {
			tracer->traceEvent(0, "[%8llu, %4u] Not enough memory for dst id struct\n",
					this->captured_stats.packets_captured, pkt_infos.flow_to_process->flow_id);
			this->captured_stats.discarded_bytes += pkt_infos.ip_offset + pkt_infos.eth_offset;
			return;
		}

		tracer->traceEvent(4, "[%8llu, %4u] new flow\n", this->captured_stats.packets_captured, pkt_infos.flow_to_process->flow_id);

		//reader->getActiveFlows()->insert({key, flow});

		/*if (ndpi_tsearch(pkt_infos.flow_to_process, &reader->getActiveFlows()[pkt_infos.hashed_index], ndpi_workflow_node_cmp) == nullptr) {
			/* Possible Leak */
		/*	this->captured_stats.discarded_bytes += pkt_infos.ip_offset + pkt_infos.eth_offset;
			return;  
		}*/

		pkt_infos.ndpi_src = pkt_infos.flow_to_process->ndpi_src;
		pkt_infos.ndpi_dst = pkt_infos.flow_to_process->ndpi_dst;
			
		this->captured_stats.total_flows_captured++;

		reader->getActiveFlows()->insert({key, flow});

		pkt_infos.tree_result = reader->getActiveFlows()->find(key);
	} 
	/* Updates timers and counters */
	FlowInfo* tmp = &pkt_infos.tree_result->second;
tmp->packets_processed++;
	printf("%llu\n", pkt_infos.tree_result->second.packets_processed);

	this->captured_stats.packets_processed++;
	pkt_infos.tree_result->second.packets_processed++;
	pkt_infos.tree_result->second.bytes_processed += pkt_infos.ip_size;

	/* update timestamp, important for timeout handling */
	pkt_infos.tree_result->second.last_seen = pkt_infos.time_ms;

	if(pkt_infos.tree_result->second.ended_dpi) {
		return;
	}
printf("prova\n");
	char src_addr_str[INET6_ADDRSTRLEN+1];
	char dst_addr_str[INET6_ADDRSTRLEN+1];
if(pkt_infos.tree_result->second.ndpi_flow == nullptr)
	printf("NULL\n");
if(pkt_infos.flow_to_process->ndpi_flow == nullptr)
	printf("2 null\n");
       //return; 	
	/* Detection protocol phase */	
	if (pkt_infos.tree_result->second.ndpi_flow->num_processed_pkts == 0xFE) {
		/* last chance to guess something, better then nothing */
		uint8_t protocol_was_guessed = 0;
		pkt_infos.tree_result->second.ended_dpi = 1;
		reader->setNewFlow(true);
		reader->setIdFlow(pkt_infos.tree_result->second.flow_id);
		printf("prova3\n");
		pkt_infos.tree_result->second.guessed_protocol =
			ndpi_detection_giveup(reader->getNdpiStruct(), pkt_infos.tree_result->second.ndpi_flow, 1, &protocol_was_guessed);
		printf("prova1\n");	
		if (protocol_was_guessed != 0) {
			/*  Protocol guessed    */
			tracer->traceEvent(3, "\t[%8llu, %4d][GUESSED] protocol: %s | app protocol: %s | category: %s\n",
					this->captured_stats.packets_captured,
					pkt_infos.tree_result->second.flow_id,
					ndpi_get_proto_name(reader->getNdpiStruct(), pkt_infos.tree_result->second.guessed_protocol.master_protocol),
					ndpi_get_proto_name(reader->getNdpiStruct(), pkt_infos.tree_result->second.guessed_protocol.app_protocol),
					ndpi_category_get_name(reader->getNdpiStruct(), pkt_infos.tree_result->second.guessed_protocol.category));
			
			this->captured_stats.protos_cnt[pkt_infos.tree_result->second.guessed_protocol.master_protocol]++;
			this->captured_stats.guessed_flow_protocols++;

			pkt_infos.tree_result->second.ipTupleToString(src_addr_str, sizeof(src_addr_str), dst_addr_str, sizeof(dst_addr_str));

			if(pkt_infos.tree_result->second.ndpi_flow->risk) {
				uint32_t j = mask & pkt_infos.tree_result->second.ndpi_flow->risk;

				for(int i=NDPI_NO_RISK; i<NDPI_MAX_RISK; i++)
					if(NDPI_ISSET_BIT(j, i) != 0) {
						
						tracer->traceEvent(1, "[** %s ** | flow %lu ] src ip: %s | dst ip: %s | src port: %u | dst port: %u\n",
								ndpi_risk2str((ndpi_risk_enum) i), pkt_infos.tree_result->second.flow_id, src_addr_str, 
								dst_addr_str, pkt_infos.tree_result->second.src_port, pkt_infos.tree_result->second.dst_port);

						if(this->flowToJson(reader, &pkt_infos.tree_result->second, 0) != 0) 
							tracer->traceEvent(0, "Error while creating the record of flow %lu\n",
									pkt_infos.tree_result->second.flow_id);

						return;
					}
			} 
			else 
				tracer->traceEvent(3, "[ flow %lu ] src ip: %s | dst ip: %s | src port: %u | dst port: %u\n", 
						pkt_infos.tree_result->second.flow_id, src_addr_str, dst_addr_str, 
						pkt_infos.tree_result->second.src_port, pkt_infos.tree_result->second.dst_port);
		} else {
			printf("prova2\n");
			tracer->traceEvent(3, "\t[%8llu, %d, %4d][FLOW NOT CLASSIFIED]\n",
					this->captured_stats.packets_captured, pkt_infos.tree_result->second.flow_id);
			this->captured_stats.unclassified_flow_protocols++;
		}

		if(generate_logs != 0) {
			if(this->flowToJson(reader, &pkt_infos.tree_result->second, 0) != 0) {
				tracer->traceEvent(0, "Error while creating the record of flow %lu\n",
						pkt_infos.tree_result->second.flow_id);
				return;
			}
		}	
	} 
	
	else {

	    pkt_infos.tree_result->second.detected_l7_protocol =
		ndpi_detection_process_packet(reader->getNdpiStruct(), pkt_infos.tree_result->second.ndpi_flow,
				pkt_infos.ip != nullptr ? (uint8_t *)pkt_infos.ip : (uint8_t *)pkt_infos.ip6,
				pkt_infos.ip_size, pkt_infos.time_ms, pkt_infos.ndpi_src, pkt_infos.ndpi_dst);

	    if (ndpi_is_protocol_detected(reader->getNdpiStruct(), pkt_infos.tree_result->second.detected_l7_protocol)) {
			if (pkt_infos.tree_result->second.detected_l7_protocol.master_protocol != NDPI_PROTOCOL_UNKNOWN ||
					pkt_infos.tree_result->second.detected_l7_protocol.app_protocol != NDPI_PROTOCOL_UNKNOWN) {

				// Protocol detected
				this->captured_stats.protos_cnt[pkt_infos.tree_result->second.detected_l7_protocol.master_protocol]++;
				this->captured_stats.detected_flow_protocols++;

				pkt_infos.tree_result->second.detection_completed = 1;
				pkt_infos.tree_result->second.ended_dpi = 1;

				pkt_infos.tree_result->second.ipTupleToString(src_addr_str, sizeof(src_addr_str), dst_addr_str, sizeof(dst_addr_str));

				reader->setNewFlow(true);
				reader->setIdFlow(pkt_infos.tree_result->second.flow_id);

				tracer->traceEvent(3, "\t[%8llu, %4d][DETECTED] protocol: %s | app protocol: %s | category: %s\n",
						this->captured_stats.packets_captured,
						pkt_infos.tree_result->second.flow_id,
						ndpi_get_proto_name(reader->getNdpiStruct(), pkt_infos.tree_result->second.detected_l7_protocol.master_protocol),
						ndpi_get_proto_name(reader->getNdpiStruct(), pkt_infos.tree_result->second.detected_l7_protocol.app_protocol),
						ndpi_category_get_name(reader->getNdpiStruct(), pkt_infos.tree_result->second.detected_l7_protocol.category));
				
				if(pkt_infos.flow_to_process->ndpi_flow->risk != 0) {
					uint32_t j = mask & pkt_infos.tree_result->second.ndpi_flow->risk;
					for(int i=NDPI_NO_RISK; i<NDPI_MAX_RISK; i++)               
						if(NDPI_ISSET_BIT(j, i) != 0) {
							tracer->traceEvent(1, "[** %s ** | flow %lu ] src ip: %s | dst ip: %s | src port: %u | dst port: %u\n",
									ndpi_risk2str((ndpi_risk_enum) i), pkt_infos.tree_result->second.flow_id, src_addr_str, 
									dst_addr_str, pkt_infos.tree_result->second.src_port, pkt_infos.tree_result->second.dst_port);
							if(this->flowToJson(reader, &pkt_infos.tree_result->second, 1) != 0) 
								tracer->traceEvent(0, "Error while creating the record of flow %lu\n",
										pkt_infos.tree_result->second.flow_id);

							return;
						} else
							tracer->traceEvent(3, "[ flow %lu ] src ip: %s | dst ip: %s | src port: %u | dst port: %u\n",
									pkt_infos.tree_result->second.flow_id, src_addr_str, dst_addr_str,
									pkt_infos.tree_result->second.src_port, pkt_infos.tree_result->second.dst_port);
				}

				if(generate_logs != 0) {
					if(this->flowToJson(reader, &pkt_infos.tree_result->second, 1) != 0) {
					tracer->traceEvent(0, "Error while creating the record of flow %lu\n",
											pkt_infos.tree_result->second.flow_id);
					return;
					}
				}
			}
        }
    }
}

