# Junos-to-eos

This repository contains miscellaneous scripts. The `junos_to_eos.py` script
can convert Juniper Junos `set` commands into an Arista EOS configuration.

## Usage

```
python junos_to_eos.py <input-file> > <output-file>
```

Where `<input-file>` is a text file containing Junos `set` style commands.
The script outputs an approximate EOS configuration which includes support for
interfaces, VLAN interfaces, BGP, OSPF, VRRP, ACLs, prefix lists, and route
maps.
