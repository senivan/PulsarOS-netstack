# Multi-interface host

Up to eight interfaces share one mbuf pool, one graph and one processing lcore.
Each interface has one IPv4 address, one RX queue and one TX queue. `app_step()`
polls every started interface and drains the graph before returning.

Legacy single-interface configuration still works. For multiple interfaces,
repeat `[interface]` sections as in `examples/multi-interface.conf`. Each section
requires `pmd`, `device` and `ip`. `lcore` and `no_huge` are global and may appear
only once. Do not mix unsectioned interface settings with sections. Duplicate
devices and local addresses are rejected. Physical PMDs require hugepages;
`no_huge=1` is accepted only when all interfaces use virtual PMDs.
The internal `app_config` and `app_runtime` layouts change; the native UDP API
signatures and legacy configuration files remain compatible.

Interface IDs follow configuration order. DPDK port IDs are resolved by device
name and need not match interface IDs. The existing packet-context ingress and
egress fields contain DPDK port IDs. Neighbours are keyed by interface ID and IP.
The bounded resolved-neighbour table has no expiry. A lookup miss starts active
ARP resolution on the selected interface, using a separate pending table.

Each configured prefix installs a connected route in a bounded, linearly scanned
table. Longest prefix wins; configuration order breaks equal-prefix ties.
Static gateway routes and route configuration are not exposed in this milestone.
The internal `route_add()` supports direct prefixes for testing; a `/0` route
there is on-link and does not imply a gateway.

UDP output follows `IPV4_ROUTE -> UDP_OUTPUT -> IPV4_OUTPUT -> ETH_OUTPUT -> TX`.
Route lookup selects the source IP before the UDP checksum is calculated and
keeps the IP destination separate from the next-hop address. TX partitions mixed
frames by egress port. Missing routes, invalid egress ports and missing neighbours
have distinct drop counters. Per-interface RX, TX and TX-drop counts are printed
at shutdown alongside driver statistics.

Ethernet accepts only the ingress MAC, plus broadcast ARP. ARP answers only for
the ingress IP. IPv4 accepts any configured local address, including one assigned
to a different interface, provided the Ethernet destination matches the ingress
interface. Nonlocal IPv4 packets are dropped with `forwarding_disabled` after
IPv4 validation; they never reach transport nodes or route lookup.

ICMP echo keeps the addressed local IP as its reply source and routes to the
requester. A reply on the ingress interface reuses the requester's Ethernet
address; a reply on another interface uses that interface's neighbour entry.
The existing UDP API binds a port across local addresses; sends select their
source from the destination route. Binding a particular local address or
interface, and returning local-address metadata on receive, remain unsupported.

RX UDP payloads are still copied into bounded queues and the receive mbuf is
freed once. UDP sends allocate a new mbuf and transfer ownership to the graph.
On a neighbour miss, ETH_OUTPUT transfers that mbuf and its context to the
pending queue. Validated ARP replies or requests update the neighbour and release
queued packets directly to ETH_OUTPUT; IPv4 and UDP headers are retained.

There are 16 pending slots, with eight packets per neighbour. Each slot sends at
most three ARP requests, one second apart, and times out one interval after the
last attempt. Failed ARP allocation or TX consumes an attempt too. Maintenance
runs after RX polling in `app_step()` using DPDK monotonic timer cycles, without
blocking. Packets sharing a pending neighbour do not trigger extra requests or
extend its deadline. Queue-full, table-full, timeout and shutdown cancellation
have separate drop counters. Timeout and shutdown free every retained mbuf.

`ps_udp_sendto()` success now means accepted for transmission or queued for
neighbour resolution. It never waits for ARP. Later timeout or TX failure is
reported through counters, without application completion events. Queued packets
are counted as accepted once; transmitting an ARP request cannot itself make a
UDP send successful. Failed resolved-table insertion leaves the pending packets
subject to the same bounded timeout policy.

## Validation

Build with CMake and run `ctest --test-dir build --output-on-failure`.
On Linux with Scapy and iproute2, run these in an isolated network namespace:

```sh
sudo unshare --net python3 tests/smoke.py "$PWD/build/netstack-dp"
sudo unshare --net python3 tests/smoke.py "$PWD/build/udp-echo" --udp
sudo unshare --net python3 tests/smoke_multi.py "$PWD/build/udp-echo"
sudo unshare --net python3 tests/smoke_arp.py "$PWD/build/test-udp-initiator"
```

CI also runs the unit suites under ASan/UBSan. The packet suite covers independent
ARP/ICMP/UDP operation, route selection and ties, interface-scoped neighbours,
invalid egress, mixed-port TX failures and mbuf returns. The two-link AF_PACKET
smoke checks both interfaces and rejects cross-interface forwarding in both
directions. It is a functional test, not a physical-NIC benchmark.
The active-ARP suite covers a silent peer, shared lookups, interface scoping,
retry deadlines, timeout, both capacity limits, malformed ARP and failure-path
ownership. CI also runs the silent-peer smoke under ASan/UBSan.

A future forwarding node can branch at the IPv4 local-delivery decision and use
the same route and neighbour lookups. It will need explicit enablement, TTL
decrement/checksum updates, MTU policy and ICMP error handling. Gateway routes
remain unconfigured; no forwarding is enabled by adding a second interface today.
