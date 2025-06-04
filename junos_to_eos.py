#!/usr/bin/env python3
"""Simple converter from Juniper Junos 'set' commands to Arista EOS configuration.

This script parses a Junos configuration in 'set' format and attempts to
convert commands into equivalent Arista EOS configuration statements. It
supports basic translations for interfaces, VLAN interfaces, BGP, OSPF, VRRP,
ACLs, prefix lists and route maps. The conversion is not exhaustive but aims
for common cases.

Usage:
    python junos_to_eos.py input_junos.txt > output_eos.txt
"""

import argparse
import re
from collections import defaultdict


def parse_args():
    parser = argparse.ArgumentParser(description="Convert Junos set commands to Arista EOS config")
    parser.add_argument("input", help="Path to file containing Junos 'set' commands")
    return parser.parse_args()


def parse_junos(lines):
    """Parse Junos set lines into structured data."""
    data = defaultdict(list)
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        # Interfaces
        m = re.match(r"set interfaces (\S+) unit (\d+) family inet address (\S+)", line)
        if m:
            iface, unit, addr = m.groups()
            data['interfaces'].append({'name': iface, 'unit': unit, 'address': addr})
            continue
        m = re.match(r"set interfaces vlan unit (\d+) family inet address (\S+)", line)
        if m:
            vlan_id, addr = m.groups()
            data['vlan_interfaces'].append({'vlan': vlan_id, 'address': addr})
            continue
        # BGP
        m = re.match(r"set protocols bgp group (\S+) peer-as (\d+)", line)
        if m:
            group, peer_as = m.groups()
            data['bgp_peer_as'][group] = peer_as
            continue
        m = re.match(r"set protocols bgp group (\S+) neighbor (\S+)", line)
        if m:
            group, neigh = m.groups()
            data['bgp_neighbors'][group].append(neigh)
            continue
        m = re.match(r"set protocols bgp group (\S+) local-as (\d+)", line)
        if m:
            group, local_as = m.groups()
            data['bgp_local_as'][group] = local_as
            continue
        # OSPF
        m = re.match(r"set protocols ospf area (\S+) interface (\S+)", line)
        if m:
            area, iface = m.groups()
            data['ospf_interfaces'].append({'area': area, 'interface': iface})
            continue
        # VRRP
        m = re.match(r"set interfaces (\S+) unit (\d+) family inet address (\S+) vrrp-group (\d+) virtual-address (\S+)", line)
        if m:
            iface, unit, addr, group_id, vip = m.groups()
            data['vrrp'].append({'interface': iface, 'unit': unit, 'group': group_id, 'vip': vip})
            continue
        # ACLs
        m = re.match(r"set firewall family inet filter (\S+) term (\S+) from (\S+.*) then (\S+)", line)
        if m:
            filter_name, term, from_clause, action = m.groups()
            data['acls'].append({'name': filter_name, 'term': term, 'from': from_clause, 'action': action})
            continue
        # Prefix lists
        m = re.match(r"set policy-options prefix-list (\S+) (\S+)", line)
        if m:
            name, prefix = m.groups()
            data['prefix_lists'][name].append(prefix)
            continue
        # Route maps (policy statements)
        m = re.match(r"set policy-options policy-statement (\S+) term (\S+) then (\S+)(?: (\S+))?", line)
        if m:
            policy, term, action, arg = m.groups()
            data['route_maps'][policy].append({'term': term, 'action': action, 'arg': arg})
            continue
    return data


def convert_to_eos(data):
    lines = []
    # Interfaces
    for iface in data.get('interfaces', []):
        name = iface['name']
        unit = iface['unit']
        addr = iface['address']
        eos_iface = f"{name}.{unit}" if unit != '0' else name
        lines.append(f"interface {eos_iface}")
        lines.append(f"   ip address {addr}")
        lines.append("!")

    # VLAN interfaces
    for vlan in data.get('vlan_interfaces', []):
        lines.append(f"interface Vlan{vlan['vlan']}")
        lines.append(f"   ip address {vlan['address']}")
        lines.append("!")

    # BGP
    bgp_local_as = next(iter(data.get('bgp_local_as', {}).values()), None)
    if bgp_local_as:
        lines.append(f"router bgp {bgp_local_as}")
        for group, neighbors in data.get('bgp_neighbors', {}).items():
            peer_as = data['bgp_peer_as'].get(group)
            for neigh in neighbors:
                lines.append(f"   neighbor {neigh} remote-as {peer_as}")
        lines.append("!")

    # OSPF
    if data.get('ospf_interfaces'):
        lines.append("router ospf 1")
        for entry in data['ospf_interfaces']:
            lines.append(f"   network {entry['interface']} area {entry['area']}")
        lines.append("!")

    # VRRP
    for v in data.get('vrrp', []):
        eos_iface = f"{v['interface']}.{v['unit']}" if v['unit'] != '0' else v['interface']
        lines.append(f"interface {eos_iface}")
        lines.append(f"   vrrp {v['group']} ip {v['vip']}")
        lines.append("!")

    # ACLs
    for acl in data.get('acls', []):
        lines.append(f"ip access-list {acl['name']}")
        entry = f"{acl['from']} {acl['action']}"
        lines.append(f"   {entry}")
        lines.append("!")

    # Prefix lists
    for name, prefixes in data.get('prefix_lists', {}).items():
        lines.append(f"ip prefix-list {name}")
        for p in prefixes:
            lines.append(f"   permit {p}")
        lines.append("!")

    # Route maps
    for name, terms in data.get('route_maps', {}).items():
        seq = 10
        for t in terms:
            lines.append(f"route-map {name} permit {seq}")
            if t['arg']:
                lines.append(f"   set {t['action']} {t['arg']}")
            else:
                lines.append(f"   set {t['action']}")
            lines.append("!")
            seq += 10

    return "\n".join(lines)


def main():
    args = parse_args()
    with open(args.input) as f:
        lines = f.readlines()
    data = parse_junos(lines)
    eos_cfg = convert_to_eos(data)
    print(eos_cfg)


if __name__ == "__main__":
    main()
