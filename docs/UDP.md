# Native UDP milestone

Build with the existing root CMake project. `netstack-dp` remains the ARP/ICMP
endpoint. `udp-echo examples/netstack.conf` runs the same endpoint with a native
application bound to UDP port 9000. Both use one lcore and one RX/TX queue.

## Application contract

`include/ps_udp.h` exposes `ps_udp_bind`, `ps_udp_recvfrom`, `ps_udp_sendto` and
`struct ps_addr`. IPv4 addresses use network byte order; ports use host order.
Call these functions on the runtime's processing lcore, between `app_step` calls.
`app_step` processes at most one RX burst and drains the graph before returning.
No blocking calls, threads, Linux descriptors or direct node-to-application
callbacks are involved.

There are eight bound endpoints, each with sixteen copied datagrams. Port zero
is rejected; duplicate bind returns `-EADDRINUSE`, and table exhaustion returns
`-ENOSPC`. Each endpoint's port supplies the queued datagram's destination port.
Receive returns the payload length, `-EAGAIN` for an empty queue, or `-EMSGSIZE`
without consuming a datagram if the supplied buffer is too small. A zero return
is a successfully received empty datagram. Queued payloads are limited to 1472
bytes; sends also respect the actual port MTU.

Send requires a bound source port and copies the caller's bytes. It returns the
payload length only when DPDK accepts the new packet. It returns `-ENOMEM` on
mbuf exhaustion, `-EMSGSIZE` for excessive size, and `-EIO` for graph/output/TX
rejection. Drop counters identify the latter cause, including
`neighbour_not_found`, `invalid_destination`, `graph_full` and `tx_failed`.
Invalid arguments return `-EINVAL`, unbound ports `-ENOENT`, and sends from
inside the graph `-EBUSY`. Success is submission, not proof of wire delivery.

## Ownership and protocol boundaries

RX follows Ethernet -> IPv4 -> UDP validation. UDP accepts checksum zero for
IPv4; a nonzero checksum covers the pseudo-header and declared UDP length.
Trailing IP bytes are excluded. The node copies payload/peer metadata into the
endpoint queue, then frees the RX mbuf. Unbound ports, malformed datagrams and
full queues go through the existing drop node, which frees the mbuf once.

TX allocates a fresh mbuf from the runtime pool. UDP_OUTPUT builds the UDP header
and nonzero software checksum. IPV4_OUTPUT prepends a 20-byte IPv4 header with
TTL 64, DF, a per-runtime incrementing ID and software checksum. ETH_OUTPUT
looks up the destination MAC and prepends Ethernet. TX preserves the existing
zero-padding and partial-send ownership policy: DPDK owns accepted packets,
and DROP frees unsent packets. Output nodes consume every submitted mbuf even
on failure. Pre-allocation API failures update output/drop-reason counters
without inventing an mbuf or a DROP-node packet.

## Neighbours and provenance

The bounded hash/probing and update pattern is adapted from
`PulsarOS-dpdk-nat/src/neigh_t.c`. ARP learning follows that project's
learn-before-reply pattern, after this stack's stricter Ethernet/ARP validation.
Only valid, on-link senders targeting the local IP are learned. Replies must
also name the local target MAC. ARP probes receive replies but are not learned.
The 64-entry table has no eviction: new keys fail when full, existing keys can
still update, and `neighbour_learn_failures` counts failed learning without
suppressing ARP replies.

IPv4 header construction adapts the field initialization pattern from
`PulsarOS-vxlan/dataplane/src/vxlan.c`; graph batching and TX ownership remain
the existing implementations. UDP uses DPDK's stable software checksum
primitives, including the RFC 768 all-ones encoding for a computed zero.
No NAT translation, VXLAN headers, VNI/FDB state or forwarding policy is copied.

Unknown neighbours fail immediately. There is no active ARP, pending queue,
retry, expiry, route or gateway. Broadcast, multicast, self-directed and
off-link UDP sends are rejected. ICMP reply construction stays unchanged.

## Validation and implications for TCP

The existing real-mbuf/null-PMD tests exercise neighbour updates and table
limits, UDP parsing/checksums, endpoint lookup and FIFO overflow, all output
headers, pool exhaustion, partial TX and fresh allocation. Run CTest normally
and with `-fsanitize=address,undefined -fno-omit-frame-pointer` compiler/linker
flags. Run `python3 tests/smoke.py /build/udp-echo --udp` in the isolated Linux
test container for AF_PACKET validation; omit `--udp` and use `netstack-dp` for
the original smoke test. The testbed adds exact-payload socket assertions and
ARP/UDP pcap artifacts on the existing two-VM topology.

TCP can reuse the same-lcore application boundary, bounded endpoint storage,
IPv4/Ethernet output nodes and explicit graph ownership. It will need its own
connection state, stream buffering and timers; UDP datagram queues do not
provide those semantics. A later public API may require endpoint lifecycle
operations and structured per-send errors. There is no close/unbind, active
resolution, zero-copy interface, fragmentation or performance claim here.
