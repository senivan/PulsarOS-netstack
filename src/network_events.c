#include "runtime.h"
#include "admin.h"

void admin_event_emit(struct app_runtime *rt, unsigned group, unsigned id, unsigned action)
{
    if (!rt->network) return;
    uint64_t seq = ++rt->events.sequence;
    rt->events.entries[(seq-1) % ADMIN_EVENT_MAX] = (struct admin_event){.sequence=seq, .generation=rt->network->generation, .group=group, .id=id, .action=action, .dev=NET_IIF_NONE};
}

void admin_neighbour_event(struct app_runtime *rt, uint16_t dev, uint32_t ip, unsigned action)
{
    admin_event_emit(rt, ADM_NEIGH, ip, action);
    if (!rt->network) return;
    struct admin_event *e=&rt->events.entries[(rt->events.sequence-1)%ADMIN_EVENT_MAX];
    e->ip=ip; e->dev=dev;
}
