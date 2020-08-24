#include "ndpi_light_includes.h"




/* ********************************** */

void ndpi_idle_scan_walker(void const * const A, ndpi_VISIT which, int depth, void * const user_data)
{
    PcapReader * const workflow = (PcapReader *)user_data;
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

    /*  Flows have the same hash, check l4_protocol */
  /*  if (flow_info_a->l4_protocol < flow_info_b->l4_protocol) {
        return(-1);
    } else if (flow_info_a->l4_protocol > flow_info_b->l4_protocol) {
        return(1);
    }*/

    /*  Have same hashval and l4, check l3 ip   */
    if (flow_info_a->ipTuplesEqual(flow_info_b) != 0 &&
        flow_info_a->src_port == flow_info_b->src_port &&
        flow_info_a->dst_port == flow_info_b->dst_port)
    {
        return(0);
    }

    /*  Last check, l3 ip and port  */
    return flow_info_a->ipTuplesCompare(flow_info_b);
}

/* ********************************** */

Reader::Reader()
{
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