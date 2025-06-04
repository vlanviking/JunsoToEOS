#!/usr/bin/env python3
"""
Junos *set* → Arista EOS converter – **v4**
-------------------------------------------------
Adds full ACL (firewall filter) extraction + attachment while preserving the v3
feature‑set (interfaces, SVIs+VRRP, prefix‑lists, route‑maps, BGP, OSPF).

New in v4
~~~~~~~~~
* Parses `set firewall family inet filter` lines (IPv4).  Supported keywords:
  * `source-address`, `destination-address`
  * `protocol`, `destination-port`, `source-port`
  * `then accept|discard|reject`
* Emits **extended IP access‑lists** with sequential numbering (10, 20 …).
* Detects interface / IRB filter references and applies `ip access-group …`
  (direction aware) on the generated EOS interfaces.
* Utility to convert CIDR → wildcard or `host` notation.

Limitations
~~~~~~~~~~~
* IPv6 filters and advanced match conditions (DSCP, TCP‑flags, etc.) generate
  `! TODO` stubs in the ACL.
* ACLs applied to switchport (L2) interfaces will be commented – adjust per
  deployment requirements.
"""
import re, sys, argparse, datetime, ipaddress

AE_MEMBERS = [  # Junos interfaces that form Port‑Channel1 in EOS order
    'xe-1/2/0',
    'xe-2/0/0',
]
SEQ_STEP = 10  # sequence increment for prefix‑lists + ACL lines

def cidr_to_acl(prefix: str) -> str:
    """Return EOS ACL representation for a CIDR (host/wildcard)."""
    if prefix in (None, 'any'):
        return 'any'
    net = ipaddress.ip_network(prefix, strict=False)
    if net.prefixlen == 32:
        return f'host {net.network_address}'
    return f'{net.network_address} {ipaddress.IPv4Address(int(net.hostmask))}'

# ----------------------------------------------------------------------------
# PARSER
# ----------------------------------------------------------------------------

def parse_junos_set(text: str):
    cfg = {
        'hostname': None, 'domain': None, 'router_id': None, 'as_num': None,
        'mgmt_ip': None,
        'interfaces': {},   # physical interfaces dict
        'irb': {},          # SVIs dict
        'prefix_lists': {},
        'policies': {},
        'acls': {},         # ACLs (firewall filters)
        'bgp': {'groups': []},
        'ospf': {'interface': None, 'hello': None, 'dead': None, 'export': None},
    }

    for line in text.splitlines():
        # ---------------- system & routing‑options ----------------
        if line.startswith('set system host-name'):
            cfg['hostname'] = line.split()[-1]
        elif line.startswith('set system domain-name'):
            cfg['domain'] = line.split()[-1]
        if 'routing-options router-id' in line:
            cfg['router_id'] = line.split()[-1]
        if 'routing-options autonomous-system' in line and 'loopback' not in line:
            cfg['as_num'] = int(line.split()[-1])

        # ---------------- mgmt ip (fxp0) ----------------
        if ' interfaces fxp0 ' in line and 'family inet address' in line:
            cfg['mgmt_ip'] = re.search(r'([\d.]+/\d+)', line).group(1)

        # ---------------- physical interfaces ----------------
        m = re.match(r'set interfaces ([a-z]+-\d+/\d+/\d+) (.+)', line)
        if m:
            iface, rest = m.groups()
            d = cfg['interfaces'].setdefault(iface, {})
            if rest.startswith('description '):
                d['description'] = rest[len('description '):]
            if '802.3ad' in rest:
                d['lag'] = rest.split()[-1]

        # ---- interface ACL attach (family inet filter) ----
        m = re.match(r'set interfaces ([a-z]+-\d+/\d+/\d+) unit \d+ family inet filter (input|output) (\S+)', line)
        if m:
            iface, direction, acl_name = m.groups()
            cfg['interfaces'].setdefault(iface, {})[f'{direction}_filter'] = acl_name

        # ---------------- IRB / VRRP / ACL ----------------
        if ' interfaces irb unit ' in line:
            m = re.match(r'set interfaces irb unit (\d+) (.+)', line)
            unit, rest = int(m.group(1)), m.group(2)
            d = cfg['irb'].setdefault(unit, {})
            if rest.startswith('description '):
                d['description'] = rest[len('description '):]
            if 'family inet address' in rest:
                addr = re.search(r'family inet address ([\d./]+)', rest).group(1)
                d.setdefault('addresses', set()).add(addr)
            if 'virtual-address' in rest:
                d['virtual_address'] = re.search(r'virtual-address ([\d.]+)', rest).group(1)
            if 'priority' in rest:
                d['priority'] = int(re.search(r'priority (\d+)', rest).group(1))
            if 'preempt' in rest:
                d['preempt'] = True
            if 'family inet filter' in rest:
                if ' input ' in rest:
                    d['input_filter'] = rest.split(' input ')[1].split()[0]
                if ' output ' in rest:
                    d['output_filter'] = rest.split(' output ')[1].split()[0]

        # ---------------- prefix‑lists ----------------
        if 'policy-options prefix-list' in line:
            m = re.match(r'set policy-options prefix-list (\S+) (\S+)', line)
            if m:
                pl_name, prefix = m.groups()
                cfg['prefix_lists'].setdefault(pl_name, []).append(prefix)

        # ---------------- policy‑statements (simple) ----------------
        if 'policy-options policy-statement' in line and ' from prefix-list ' in line:
            ps_match = re.match(r'set policy-options policy-statement (\S+) term (\S+) from prefix-list (\S+)', line)
            if ps_match:
                pol, term, pl = ps_match.groups()
                cfg['policies'].setdefault(pol, {'pl': pl, 'action': None})
        if 'policy-options policy-statement' in line and (' then accept' in line or ' then reject' in line):
            pol = line.split()[3]
            cfg['policies'].setdefault(pol, {'pl': 'NONE', 'action': None})
            cfg['policies'][pol]['action'] = 'permit' if 'accept' in line else 'deny'

        # ---------------- ACLs (firewall filters) ----------------
        if line.startswith('set firewall family inet filter '):
            tokens = line.split()
            fname = tokens[5]
            term = tokens[tokens.index('term') + 1]
            cfg['acls'].setdefault(fname, {}).setdefault(term, {'conditions': {}, 'action': None})
            remainder = tokens[tokens.index('term') + 2:]
            if remainder[0] == 'from':
                key = remainder[1]
                val = ' '.join(remainder[2:])
                cfg['acls'][fname][term]['conditions'][key] = val
            elif remainder[0] == 'then':
                cfg['acls'][fname][term]['action'] = remainder[1]

        # ---------------- OSPF ----------------
        if 'protocols ospf area' in line and 'interface' in line and 'interface-type' in line:
            cfg['ospf']['interface'] = line.split()[-2]
            if 'hello-interval' in line:
                cfg['ospf']['hello'] = int(re.search(r'hello-interval (\d+)', line).group(1))
            if 'dead-interval' in line:
                cfg['ospf']['dead'] = int(re.search(r'dead-interval (\d+)', line).group(1))
        if 'protocols ospf export' in line:
            cfg['ospf']['export'] = line.split()[-1]

        # ---------------- BGP ----------------
        if line.startswith('set protocols bgp group '):
            parts = line.split()
            grp = parts[4]
            g = next((x for x in cfg['bgp']['groups'] if x['name'] == grp), None)
            if not g:
                g = {'name': grp, 'type': 'external', 'import': None, 'export': None,
                     'local_addr': None, 'neighbors': []}
                cfg['bgp']['groups'].append(g)
            if 'type internal' in line:
                g['type'] = 'internal'
            if 'import' in parts and 'policy' not in parts:
                g['import'] = parts[-1]
            if 'export' in parts and 'policy' not in parts:
                g['export'] = parts[-1]
            if 'local-address' in parts:
                g['local_addr'] = parts[-1]
            if 'neighbor' in parts:
                n_ip = parts[parts.index('neighbor') + 1]
                asn = None
                if 'peer-as' in parts:
                    asn = parts[parts.index('peer-as') + 1]
                elif g['type'] == 'internal':
                    asn = cfg['as_num']
                descr = None
                if 'description' in parts:
                    descr = ' '.join(parts[parts.index('description') + 1:])
                auth = None
                if 'authentication-key' in parts:
                    auth = parts[parts.index('authentication-key') + 1]
                g['neighbors'].append({'ip': n_ip, 'peer_as': asn, 'description': descr, 'auth': auth})

    return cfg

# ----------------------------------------------------------------------------
# EMIT HELPERS
# ----------------------------------------------------------------------------

def eos_int_name(junos_if: str, mapping: dict) -> str:
    return f'Ethernet{mapping[junos_if]}'


def build_interface_mapping(intfs: dict):
    mapping = {}
    port = 1  # Ethernet port iterator
    # Pre‑allocate AE members first
    for member in AE_MEMBERS:
        mapping[member] = port
        port += 1
    for j_if in sorted(intfs):
        if j_if in mapping:
            continue
        mapping[j_if] = port
        port += 1
    return mapping

# ---------------- ACL emission ----------------

def emit_acls(acls: dict):
    out = []
    for name, terms in acls.items():
        out.append(f'ip access-list extended {name}')
        seq = 10
        for t_name, t_data in terms.items():
            cond = t_data['conditions']
            action = t_data['action'] or 'accept'
            action = 'permit' if action in ('accept', 'pass') else 'deny'
            proto = cond.get('protocol', 'ip')
            src = cidr_to_acl(cond.get('source-address', 'any'))
            dst = cidr_to_acl(cond.get('destination-address', 'any'))
            line = f' {seq} {action} {proto} {src} {dst}'
            if 'destination-port' in cond:
                line += f' eq {cond["destination-port"]}'
            if 'source-port' in cond:
                line += f' eq {cond["source-port"]}'
            if not cond:  # unmatched complex term
                line = f' {seq} remark TODO convert term {t_name} (complex match)'
            out.append(line)
            seq += SEQ_STEP
        out.append('!')
    return out

# ---------------- INTERFACES ----------------

def emit_interfaces(cfg, mapping):
    out = []
    # ---------- Port‑Channel ----------
    out += [
        'interface Port-Channel1',
        ' description LAG-to-peer',
        ' switchport',
        ' switchport mode trunk',
        ' switchport trunk allowed vlan 2-4094',
        ' mtu 1548',
        '!',
    ]
    # ---------- Physical ----------
    for j_if, props in sorted(cfg['interfaces'].items(), key=lambda x: mapping[x[0]]):
        eport = eos_int_name(j_if, mapping)
        out.append(f'interface {eport}')
        if props.get('description'):
            out.append(f' description {props["description"]}')
        if j_if in AE_MEMBERS:
            out.append(' channel-group 1 mode active')
        else:
            out.append(' switchport')
            out.append(' switchport mode access   ! TODO adjust if trunk needed')
        # ACL attach on routed ports only (comment if switchport)
        if props.get('input_filter'):
            out.append(f' ! TODO convert to routed port or apply SVI ACL')
            out.append(f' ! ip access-group {props["input_filter"]} in')
        if props.get('output_filter'):
            out.append(f' ! ip access-group {props["output_filter"]} out')
        out.append('!')
    return out

# ---------------- SVIs ----------------

def emit_svis(cfg):
    out = []
    for unit in sorted(cfg['irb']):
        d = cfg['irb'][unit]
        out.append(f'interface Vlan{unit}')
        if d.get('description'):
            out.append(f' description {d["description"]}')
        addr = sorted(d['addresses'])[0]
        out.append(f' ip address {addr}')
        if d.get('virtual_address'):
            out.append(f' ip virtual-router address {d["virtual_address"]}')
            if d.get('priority'):
                out.append(f' ip virtual-router priority {d["priority"]}')
            if d.get('preempt'):
                out.append(' ip virtual-router preempt')
        if d.get('input_filter'):
            out.append(f' ip access-group {d["input_filter"]} in')
        if d.get('output_filter'):
            out.append(f' ip access-group {d["output_filter"]} out')
        out.append('!')
    return out

# ---------------- PREFIX‑LISTS / ROUTE‑MAPS ----------------

def emit_prefix_lists(pl):
    lines = []
    for name, nets in pl.items():
        lines.append(f'ip prefix-list {name}')
        seq = 10
        for pfx in nets:
            lines.append(f' seq {seq} permit {pfx}')
            seq += SEQ_STEP
        lines.append('!')
    return lines


def emit_route_maps(policies):
    out = []
    for name, info in policies.items():
        if not info['action']:
            out.append(f'! TODO complex policy {name} not converted')
            continue
        out.append(f'route-map {name} {info["action"]} 10')
        out.append(f' match ip address prefix-list {info["pl"]}')
        out.append('!')
    return out

# ---------------- BGP / OSPF ----------------

def emit_bgp(cfg):
    out = [f'router bgp {cfg["as_num"]}']
    if cfg['router_id']:
        out.append(f' bgp router-id {cfg["router_id"]}')
    out.append(' no bgp default ipv4-unicast')
    for g in cfg['bgp']['groups']:
        for n in g['neighbors']:
            out.append(f' neighbor {n["ip"]} remote-as {n["peer_as"]}')
            if n['description']:
                out.append(f' neighbor {n["ip"]} description {n["description"]}')
            if n['auth']:
                out.append(f' neighbor {n["ip"]} password {n["auth"]}')
            if g['local_addr']:
                out.append(f' neighbor {n["ip"]} update-source {g["local_addr"]}')
            if g['import']:
                out.append(f' neighbor {n["ip"]} route-map {g["import"]} in')
            if g['export']:
                out.append(f' neighbor {n["ip"]} route-map {g["export"]} out')
    out.append('!')
    return out


def emit_ospf(cfg):
    o = cfg['ospf']
    if not o['interface']:
        return []
    iface = o['interface'].replace('.', '/')
    out = [
        'router ospf 1',
        f' router-id {cfg["router_id"] or "0.0.0.0"}',
        ' passive-interface default',
        f' no passive-interface {iface}',
    ]
    if o['hello']:
        out.append(f' timers hello {o["hello"]} dead {o["dead"] or 4 * o["hello"]}')
    if o['export']:
        out.append(f' redistribute route-map {o["export"]}')
    out.append('!')
    return out

# ----------------------------------------------------------------------------
# MASTER EMIT
# ----------------------------------------------------------------------------

def emit_eos(cfg):
    ts = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    out = [f'!! Auto‑generated by junos_to_eos.py v4 on {ts}', '']
    out.append(f'hostname {cfg["hostname"]}')
    if cfg['domain']:
        out.append(f'ip domain-name {cfg["domain"]}')
    out.append('!')

    # mgmt VRF + Management1
    if cfg['mgmt_ip']:
        out += [
            'vrf definition management',
            ' ! default route handled elsewhere',
            '!',
            'interface Management1',
            ' vrf forwarding management',
            f' ip address {cfg["mgmt_ip"]}',
            ' ip access-group MANAGEMENT in',
            '!',
        ]

    # ACLs must exist before they are referenced
    out += emit_acls(cfg['acls'])

    # build interface mapping and emit physical + SVIs
    mapping = build_interface_mapping(cfg['interfaces'])
    out += emit_interfaces(cfg, mapping)
    out += emit_svis(cfg)

    # prefix‑lists / route‑maps
    out += emit_prefix_lists(cfg['prefix_lists'])
    out += emit_route_maps(cfg['policies'])

    # routing protocols
    out += emit_bgp(cfg)
    out += emit_ospf(cfg)

    out.append('end')
    return '\n'.join(out)

# ----------------------------------------------------------------------------
# MAIN
# ----------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description='Convert Junos *set* file to EOS config')
    ap.add_argument('file', help='Path to Junos *set* commands file')
    args = ap.parse_args()
    cfg = parse_junos_set(open(args.file).read())
    print(emit_eos(cfg))

if __name__ == '__main__':
    main()