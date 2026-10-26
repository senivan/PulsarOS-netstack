#include "runtime.h"

void admin_event_emit(struct app_runtime *rt, unsigned group, unsigned id, unsigned action)
{
    if (!rt->network) return;
    uint64_t seq = ++rt->events.sequence;
    rt->events.entries[(seq-1) % ADMIN_EVENT_MAX] = (struct admin_event){seq, rt->network->generation, group, id, action};
}
