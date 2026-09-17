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
The bounded neighbour table still uses passive ARP learning and has no expiry.

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
The graph frees rejected packets and TX retains ownership only of accepted ones.

## Validation

Build with CMake and run `ctest --test-dir build --output-on-failure`.
On Linux with Scapy and iproute2, run these in an isolated network namespace:

```sh
sudo unshare --net python3 tests/smoke.py "$PWD/build/netstack-dp"
sudo unshare --net python3 tests/smoke.py "$PWD/build/udp-echo" --udp
sudo unshare --net python3 tests/smoke_multi.py "$PWD/build/udp-echo"
```

CI also runs the unit suites under ASan/UBSan. The packet suite covers independent
ARP/ICMP/UDP operation, route selection and ties, interface-scoped neighbours,
invalid egress, mixed-port TX failures and mbuf returns. The two-link AF_PACKET
smoke checks both interfaces and rejects cross-interface forwarding in both
directions. It is a functional test, not a physical-NIC benchmark.

A future forwarding node can branch at the IPv4 local-delivery decision and use
the same route and neighbour lookups. It will need explicit enablement, TTL
decrement/checksum updates, MTU policy and ICMP error handling. Gateway routes and
active neighbour resolution require separate decisions; no forwarding is enabled
by adding a second interface today.
