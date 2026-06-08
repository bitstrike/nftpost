# nftpost

A terminal UI firewall rule manager for Linux that lets you build nftables
rulesets using the iptables paradigm you already know. Configure rules in
familiar iptables terms -- chains, protocols, ports, states, actions -- and
nftpost generates the corresponding nftables or iptables-save scripts ready
to apply to your system.

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-GPLv3-green)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey)

---

## Features

- **iptables-familiar interface** -- INPUT, FORWARD, OUTPUT, NAT chains with
  ACCEPT/DROP/REJECT/LOG actions, state matching, protocol/port filtering,
  source/destination IP and interface matching
- **Full nftables output** -- generates a `nft -f` compatible script with
  targeted table flushes (preserves existing iptables-nft rules)
- **iptables-save output** -- generates an `iptables-restore` compatible save
  file for use with `iptables-nft` shim environments
- **User-defined chains** -- create named chains in filter, nat, or mangle
  tables; jump to them from any rule in the same table
- **Multiple saved configs** -- SQLite database at `~/.nftpost.db` stores
  named configurations; load, modify, and save-as at any time
- **256-color TUI** -- Turbo-C style form dialogs, fixed-width rule table
  with `...` truncation, color-coded status messages
- **No external dependencies** -- pure Python standard library (`curses`,
  `sqlite3`, `argparse`, `tempfile`)

---

## Requirements

- Python 3.8+
- Linux with nftables kernel support
- A 256-color terminal (or use `-8` for 8-color fallback)

---

## Installation

```bash
git clone https://github.com/youruser/nftpost.git
cd nftpost
chmod +x nftpost.py
```

Optionally install to your PATH:

```bash
sudo cp nftpost.py /usr/local/bin/nftpost
```

---

## Usage

```bash
# Start with 256-color mode (default)
./nftpost.py

# Start with 8-color fallback (limited terminals)
./nftpost.py -8

# Show help and keybind reference
./nftpost.py -h
```

---

## Keybinds

### Main screen

| Key | Action |
|-----|--------|
| `q` | Quit |
| `l` | Load config (or create a new blank config) |
| `s` | Save config (overwrite or save as new name) |
| `a` | Add rule to current chain |
| `i` | Insert rule before selected rule |
| `e` / `Enter` | Edit selected rule |
| `d` | Delete selected rule |
| `o` | Reorder rule (move before/after another) |
| `p` | Set default policy for current chain |
| `n` | Create new user-defined chain |
| `x` | Delete user-defined chain |
| `g` | Generate output script |

### Navigation

| Key | Action |
|-----|--------|
| `Up` / `Down` | Navigate chains (left panel) or rules (right panel) |
| `Tab` / `Left` / `Right` | Toggle focus between chain list and rule list |
| `Esc` | Cancel / go back |

### Rule form dialog

| Key | Action |
|-----|--------|
| `Tab` / `Up` / `Down` | Move between fields |
| `Enter` | Edit text field / open picker for enum fields |
| `Esc` (in field) | Discard field edit, return to navigation |
| `Esc` (navigating) | Cancel dialog without saving |
| `F10` / `s` | Save rule |

---

## Chains

### Built-in chains

| Chain | Table | Policy |
|-------|-------|--------|
| INPUT | filter | configurable (ACCEPT/DROP) |
| FORWARD | filter | configurable |
| OUTPUT | filter | configurable |
| NAT PREROUTING | nat | - |
| NAT INPUT | nat | - |
| NAT OUTPUT | nat | - |
| NAT POSTROUTING | nat | - |
| MANGLE | mangle | - |

### User-defined chains

Create named chains with `n` and assign them to the filter, nat, or mangle
table. Rules in any chain of the same table can jump to a user chain using
`-> CHAINNAME` as the action. User chains appear below the built-in chains
in the left panel, labeled with their table (`[f]`, `[n]`, `[m]`).

---

## Rule fields

### Filter / Mangle rules

| Field | Description | Example |
|-------|-------------|---------|
| Protocol | Layer 4 protocol or ANY | `TCP`, `UDP`, `ICMP` |
| Dest Port | Destination port or range | `443`, `8080:8090` |
| Src Port | Source port or range | `1024:65535` |
| Source IP | Source address or CIDR | `10.0.0.0/8` |
| Dest IP | Destination address or CIDR | `192.168.1.0/24` |
| In Interface | Incoming network interface | `eth0`, `bond0` |
| Out Interface | Outgoing network interface | `eth1` |
| State | Connection tracking state | `NEW`, `RELATED,ESTABLISHED` |
| Action | Terminal action or chain jump | `ACCEPT`, `DROP`, `-> LOGDROP` |
| Comment | Optional rule description | `Allow SSH from LAN` |

Leave any field blank (or `ANY`) to omit that match condition.

The SRC and DST columns in the rule list combine IP and interface into a
single display value: `eth0|10.0.0.0/8`. Long values truncate to `...`.

### NAT rules

| Field | Description |
|-------|-------------|
| Protocol | Layer 4 protocol or ANY |
| Source IP | Source address/CIDR |
| Dest IP | Destination address/CIDR |
| Dest Port | Destination port |
| NAT Action | `DNAT`, `SNAT`, or `MASQUERADE` |
| To Destination | Target address for DNAT/SNAT (e.g. `192.168.1.10:80`) |
| Comment | Optional description |

---

## Output formats

Pressing `g` opens a format picker:

**nft script** (`.nft`) -- apply with:
```bash
sudo nft -f /tmp/nftpost_XXXXX.nft
```

Uses targeted `delete table` flushes rather than `flush ruleset`, so
existing rules managed outside nftpost (including iptables-nft rules in
other tables) are preserved.

**iptables-save** (`.ipt`) -- apply with:
```bash
sudo iptables-restore < /tmp/nftpost_XXXXX.ipt
```

Produces a standard three-table (`*filter`, `*nat`, `*mangle`) restore file.
`LOG,ACCEPT` / `LOG,DROP` / `LOG,REJECT` compound actions are split into two
consecutive rules as required by iptables-save format.

**Both** -- generates both files in one operation.

> **Note for iptables-nft users:** On Debian 10+, Ubuntu 20.04+, and RHEL 8+,
> `iptables` is typically the `iptables-nft` shim which stores rules inside
> the nftables kernel subsystem. Check with `iptables --version` -- if it
> shows `(nf_tables)` you are on the shim. The nft script format is the
> preferred output in this case.

---

## Configuration database

nftpost stores all configs in `~/.nftpost.db` (SQLite). Multiple named
configurations can be saved, loaded, and generated independently.

When saving to a new name, the default is pre-filled with a timestamp
(`YYYY-MM-DD_HH:MM:SS`) to avoid accidentally overwriting an existing config.

---

## License

nftpost is released under the [GNU General Public License v3.0](LICENSE).

Copyright (C) 2024 -- see source for authorship.

You are free to use, modify, and distribute this software under the terms
of the GPLv3. See the [GNU GPL website](https://www.gnu.org/licenses/gpl-3.0.html)
for the full license text.

---

## Contributing

Bug reports and patches welcome. Please open an issue or pull request on GitHub.

When contributing, please maintain the zero-external-dependency policy --
only Python standard library imports are permitted.
