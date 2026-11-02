"""Explicit bounded datasets. Counts refer to total active software routes."""
from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class Case:
    name: str
    group: str = 'forward'
    size: int = 128
    rate: int = 0
    routes: int = 1
    pattern: str = 'stable'
    policies: int = 0
    empty_tables: bool = False
    acl: int = 0
    acl_pattern: str = 'miss'
    neighbours: int = 1
    addresses: int = 1
    services: int = 1
    kind: str = 'udp'
    mode: str = 'rr'
    connections: int = 1
    payload: int = 64
    latency: bool = False
    cold: bool = False
    unresolved: bool = False
    change: bool = False

    def data(self):
        return asdict(self)


def matrix(profile):
    cases = []
    if profile == 'quick':
        return [Case('calibration_128', 'calibration'), Case('forward_128_rate1000', rate=1000),
                Case('route_change', 'correctness', rate=1000, routes=8, change=True),
                Case('acl_drop', 'acl', rate=1000, acl=8, acl_pattern='drop')]
    for size in (60, 128, 512, 1514):
        cases.append(Case(f'calibration_{size}', 'calibration', size=size))
        rates = (1000, 10000, 25000, 50000, 100000, 250000, 0) if profile == 'full' else (0,)
        for rate in rates:
            cases.append(Case(f'forward_{size}_rate{rate}', size=size, rate=rate))
    if profile == 'standard':
        for rate in (1000, 50000, 100000, 250000):
            cases.append(Case(f'forward_128_rate{rate}', rate=rate))
    for routes in ((1, 8, 32, 128, 256, 512, 1024) if profile == 'full' else (1, 8, 32, 128, 256)):
        patterns = ('stable', 'multiple', 'worst', 'random') if profile == 'full' else ('stable',)
        for pattern in patterns:
            cases.append(Case(f'route_{routes}_{pattern}', 'route', routes=routes, pattern=pattern))
    for count in (0, 1, 8, 32):
        cases.append(Case(f'policy_{count}', 'policy', routes=256, policies=count))
    cases.append(Case('policy_32_empty', 'policy', routes=256, policies=32, empty_tables=True))
    for count in ((0, 8, 32, 128, 512, 2048) if profile == 'full' else (0, 8, 32, 128)):
        patterns = ('miss', 'early', 'late', 'mixed') if profile == 'full' and count else ('miss',)
        for pattern in patterns:
            cases.append(Case(f'acl_{count}_{pattern}', 'acl', acl=count, acl_pattern=pattern))
    if profile == 'standard':
        for pattern in ('early', 'late', 'mixed'):
            cases.append(Case(f'acl_128_{pattern}', 'acl', acl=128, acl_pattern=pattern))
    cases.append(Case('acl_drop', 'acl', rate=10000, acl=8, acl_pattern='drop'))
    for count in (1, 16, 48, 64):
        cases.append(Case(f'neighbours_{count}', 'neighbour', neighbours=count))
    cases += [Case('neighbour_cold', 'neighbour', rate=100, cold=True),
              Case('neighbour_unresolved', 'neighbour', routes=2, rate=10, unresolved=True),
              Case('addresses_64_forward', 'address', addresses=64, routes=2)]
    for rate in (1000, 50000, 0):
        cases.append(Case(f'latency_rate{rate}', 'latency', rate=rate, routes=2, latency=True))
    for count in (1, 2, 4):
        cases.append(Case(f'udp_{count}_rr', 'application', services=count))
    cases += [Case('udp_receiver', 'application', mode='sink', rate=0),
              Case('udp_addresses_64', 'application', mode='sink', addresses=64, rate=0)]
    for mode in ('connect', 'short', 'rr', 'bulk'):
        cases.append(Case(f'tcp_{mode}', 'application', kind='tcp', mode=mode, payload=4096 if mode == 'bulk' else 64))
    cases.append(Case('tcp_bulk_4', 'application', kind='tcp', mode='bulk', connections=4, payload=4096))
    cases.append(Case('route_change', 'correctness', routes=8, rate=1000, change=True))
    return cases


def eligible(case, engine, profile):
    if case.group == 'calibration':
        return engine == 'calibration'
    if engine == 'calibration':
        return False
    if engine in ('current', 'before') and (case.routes > 256 or case.acl > 128):
        return False
    if engine == 'before':
        return case.name in ('forward_128_rate0', 'route_256_worst', 'route_256_stable', 'policy_32_empty', 'addresses_64_forward', 'acl_128_miss', 'udp_1_rr', 'udp_receiver', 'tcp_rr', 'tcp_bulk')
    if engine == 'linux' and profile == 'standard':
        return case.group in ('forward', 'application', 'latency') or case.name in ('route_256_stable', 'policy_32_empty', 'acl_128_miss', 'acl_drop')
    return True


def unsupported():
    return [{'engines': ['current', 'before'], 'group': 'route', 'count': count, 'reason': 'NET_ROUTE_MAX=256; production capacity unchanged'} for count in (512, 1024)] + [
        {'engines': ['current', 'before'], 'group': 'acl', 'count': count, 'reason': 'NET_ACL_MAX=128; reference classifier and production capacity unchanged'} for count in (512, 2048)]
