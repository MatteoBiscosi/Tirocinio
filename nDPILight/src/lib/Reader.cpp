#include "ndpi_light_includes.h"




/* ********************************** */

void ndpi_idle_scan_walker(void const * const A, ndpi_VISIT which, int depth, void * const user_data)
{
    Reader * const workflow = (Reader *)user_data;
    FlowInfo * const flow = *(FlowInfo **)A;

    (void)depth;

    if (workflow == nullptr || flow == nullptr) {
        return;
    }

    if (which == ndpi_preorder || which == ndpi_leaf) {
        if ((flow->flow_fin_ack_seen == 1 && flow->flow_ack_seen == 1) ||
            flow->last_seen + MAX_IDLE_TIME < workflow->getLastTime())
            /*  New flow that need to be added to idle flows    */
        {
            char src_addr_str[INET6_ADDRSTRLEN+1];
            char dst_addr_str[INET6_ADDRSTRLEN+1];
            flow->ipTupleToString(src_addr_str, sizeof(src_addr_str), dst_addr_str, sizeof(dst_addr_str));
            workflow->incrCurIdleFlows();
            workflow->getNdpiFlowsIdle()[workflow->getCurIdleFlows()] = flow;
            workflow->incrTotalIdleFlows();
        }
    }
}

/* ********************************** */

int ndpi_workflow_node_cmp(void const * const A, void const * const B)
{
    FlowInfo * const flow_info_a = (FlowInfo *)A;
    FlowInfo * const flow_info_b = (FlowInfo *)B;

    if(flow_info_a == nullptr || flow_info_b == nullptr) {
        return -1;
    }

    /*  Check hashval   */
    if (flow_info_a->hashval < flow_info_b->hashval) {
        return(-1);
    } else if (flow_info_a->hashval > flow_info_b->hashval) {
        return(1);
    }

    /*  Have same hashval and l4, check l3 ip   */
    if(flow_info_a->l3_type == L3_IP && flow_info_b->l3_type == L3_IP) { /* IPv4 */
        if (((flow_info_a->ip_tuple.v4.src == flow_info_b->ip_tuple.v4.src &&  /* Check if A->src == flow_info_b->src */
              flow_info_a->ip_tuple.v4.dst == flow_info_b->ip_tuple.v4.dst) || 
             (flow_info_a->ip_tuple.v4.dst == flow_info_b->ip_tuple.v4.src &&  /* Check if A->dst == flow_info_b->src */
              flow_info_a->ip_tuple.v4.src == flow_info_b->ip_tuple.v4.dst)) &&
            ((flow_info_a->src_port == flow_info_b->src_port &&  /* Check if A->src.port == flow_info_b->src.port */
              flow_info_a->dst_port == flow_info_b->dst_port) ||
             (flow_info_a->dst_port == flow_info_b->src_port &&  /* Check if A->dst.port == flow_info_b->src.port */
              flow_info_a->src_port == flow_info_b->dst_port)))
            
            return 0;

    } else if(flow_info_a->l3_type == L3_IP6 && flow_info_b->l3_type == L3_IP6) { /* IPv6 */
        if (((flow_info_a->ip_tuple.v6.src[0] == flow_info_b->ip_tuple.v6.src[0] &&  /* Check if A->src == flow_info_b->src */
              flow_info_a->ip_tuple.v6.src[1] == flow_info_b->ip_tuple.v6.src[1] &&
              flow_info_a->ip_tuple.v6.dst[0] == flow_info_b->ip_tuple.v6.dst[0] &&
              flow_info_a->ip_tuple.v6.dst[1] == flow_info_b->ip_tuple.v6.dst[1]) ||
             (flow_info_a->ip_tuple.v6.dst[0] == flow_info_b->ip_tuple.v6.src[0] &&  /* Check if A->dst == flow_info_b->src */
              flow_info_a->ip_tuple.v6.dst[1] == flow_info_b->ip_tuple.v6.src[1] &&
              flow_info_a->ip_tuple.v6.src[0] == flow_info_b->ip_tuple.v6.dst[0] &&
              flow_info_a->ip_tuple.v6.src[1] == flow_info_b->ip_tuple.v6.dst[1])) &&
            ((flow_info_a->src_port == flow_info_b->src_port &&  /* Check if A->src.port == flow_info_b->src.port */
              flow_info_a->dst_port == flow_info_b->dst_port) ||
             (flow_info_a->dst_port == flow_info_b->src_port &&  /* Check if A->dst.port == flow_info_b->src.port */
              flow_info_a->src_port == flow_info_b->dst_port)))
            
            return 0;
    }

    /*  IPv4    */
    if (flow_info_a->l3_type == L3_IP && flow_info_b->l3_type == L3_IP) {
        if (flow_info_a->ip_tuple.v4.src < flow_info_b->ip_tuple.v4.src ||
            flow_info_a->ip_tuple.v4.dst < flow_info_b->ip_tuple.v4.dst)
        {
            /*  Minor   */
            return -1;
        }
        if (flow_info_a->ip_tuple.v4.src > flow_info_b->ip_tuple.v4.src ||
            flow_info_a->ip_tuple.v4.dst > flow_info_b->ip_tuple.v4.dst)
        {
            /*  Major   */
            return 1;
        }
        /*  IPv6    */
    } else if (flow_info_a->l3_type == L3_IP6 && flow_info_b->l3_type == L3_IP6) {
        if ((flow_info_a->ip_tuple.v6.src[0] < flow_info_b->ip_tuple.v6.src[0] &&
             flow_info_a->ip_tuple.v6.src[1] < flow_info_b->ip_tuple.v6.src[1]) ||
            (flow_info_a->ip_tuple.v6.dst[0] < flow_info_b->ip_tuple.v6.dst[0] &&
             flow_info_a->ip_tuple.v6.dst[1] < flow_info_b->ip_tuple.v6.dst[1]))
        {
            /*  Minor   */
            return -1;
        }
        if ((flow_info_a->ip_tuple.v6.src[0] > flow_info_b->ip_tuple.v6.src[0] &&
             flow_info_a->ip_tuple.v6.src[1] > flow_info_b->ip_tuple.v6.src[1]) ||
            (flow_info_a->ip_tuple.v6.dst[0] > flow_info_b->ip_tuple.v6.dst[0] &&
             flow_info_a->ip_tuple.v6.dst[1] > flow_info_b->ip_tuple.v6.dst[1]))
        {
            /*  Major   */
            return 1;
        }
    }
    /*  Port    */
    if (flow_info_a->src_port < flow_info_b->src_port ||
        flow_info_a->dst_port < flow_info_b->dst_port)
    {
        /*  Minor   */
        return -1;
    } else if (flow_info_a->src_port > flow_info_b->src_port ||
               flow_info_a->dst_port > flow_info_b->dst_port)
    {
        /*  Major   */
        return 1;
    }
}

/* ********************************** */
/*
Reader::Reader()
{
    this->thread_number = 1;
    this->ndpi_flows_active = nullptr;
    this->ndpi_flows_idle = nullptr;
    this->error_or_eof = 0;
    this->ndpi_struct = nullptr;
}
*/
/* ********************************** */

Reader::Reader(char *log_path, const char *type)
{
    printf("Inside reader\n");
    if(log_path != nullptr)
    	strcpy(this->log_path, log_path);
    this->type = type;
    this->ndpi_flows_active = nullptr;
    this->ndpi_flows_idle = nullptr;
    this->error_or_eof = 0;
    this->ndpi_struct = nullptr;
}

/* ********************************** */

Reader::~Reader()
{
    if (this->ndpi_struct != nullptr) {
        ndpi_exit_detection_module(this->ndpi_struct);
    }

    if(this->ndpi_flows_active != nullptr) {
        for(size_t i = 0; i < this->max_active_flows; i++) {
            ndpi_tdestroy(this->ndpi_flows_active[i], flowFreer);
        }
    }

    if(this->ndpi_flows_active != nullptr)
        ndpi_free(this->ndpi_flows_active);

    if(this->ndpi_flows_idle != nullptr)
        ndpi_free(this->ndpi_flows_idle);
}   

/* ********************************** */

int Reader::newFlow(FlowInfo * & flow_to_process) {
    if (this->cur_active_flows == this->max_active_flows) {
        tracer->traceEvent(0, "[10] max flows to track reached: %llu, idle: %llu\n",
                                this->max_active_flows, this->cur_idle_flows);
        return -1;
    }

    flow_to_process = (FlowInfo *)ndpi_malloc(sizeof(*flow_to_process));
    if (flow_to_process == nullptr) {
        tracer->traceEvent(0, "[10] Not enough memory for flow info\n");
        return -1;
    }

    this->cur_active_flows++;
    this->total_active_flows++;

    return 0;
}

/* ********************************** */
