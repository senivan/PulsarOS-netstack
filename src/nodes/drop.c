#include "internal.h"

void drop_node_run(struct app_runtime *rt, const struct node_frame *in,
                   struct node_output *out)
{
    (void)out;
    rt->graph.nodes[NODE_DROP].stats.drops += in->count;
    for (uint16_t i = 0; i < in->count; i++) {
        uint8_t reason = in->ctxs[i].drop_reason;
        if (reason < DROP_REASON_MAX) rt->graph.drop_reasons[reason]++;
        rte_pktmbuf_free(in->pkts[i]);
    }
}
