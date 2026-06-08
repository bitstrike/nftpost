#!/usr/bin/env python3
"""
nftpost v0.5 -- iptables-paradigm nftables rule generator
TUI for building nftables configs from a familiar iptables-style interface.
"""

import curses
import sqlite3
import os
import sys
import tempfile
import textwrap
from dataclasses import dataclass, field
from typing import Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

APP_VERSION = "v0.6"
DB_PATH = os.path.expanduser("~/.nftpost.db")

FILTER_CHAINS  = ["INPUT", "FORWARD", "OUTPUT"]
NAT_CHAINS     = ["NAT PREROUTING", "NAT INPUT", "NAT OUTPUT", "NAT POSTROUTING"]
MANGLE_CHAINS  = ["MANGLE"]
BUILTIN_CHAINS = MANGLE_CHAINS + NAT_CHAINS + FILTER_CHAINS

# Tables user chains can belong to
USER_CHAIN_TABLES = ["filter", "nat", "mangle"]

# Chains that support a default policy in nftables
POLICY_CHAINS = FILTER_CHAINS

VALID_POLICIES    = ["ACCEPT", "DROP"]
VALID_PROTOS      = ["ANY", "TCP", "UDP", "ICMP", "ICMPv6", "ESP", "AH", "GRE", "SCTP"]
VALID_STATES      = ["ANY", "NEW", "ESTABLISHED", "RELATED", "RELATED,ESTABLISHED", "INVALID"]
VALID_ACTIONS     = ["ACCEPT", "DROP", "REJECT", "LOG", "LOG,ACCEPT", "LOG,DROP", "LOG,REJECT"]
VALID_NAT_ACTIONS = ["DNAT", "SNAT", "MASQUERADE"]

# Rule table column widths (characters, not including separator space)
# Row prefix "NN. " costs 4 chars; total = COL_NUM + all cols + separators
COL_NUM     =  4   # "NN. "
COL_PROTO   =  6   # TCP, UDP, ICMP...
COL_DPORT   =  8   # port or range
COL_SRC     = 18   # src IP/CIDR
COL_DST     = 18   # dst IP/CIDR
COL_STATE   = 22   # RELATED,ESTABLISHED is the longest
COL_ACTION  = 12   # LOG,REJECT + user chain names
COL_TODEST  = 20   # DNAT to-destination
COL_COMMENT = 20   # trailing comment (filter only, fills remainder)

# Color pair IDs
CP_NORMAL     = 1
CP_HIGHLIGHT  = 2
CP_TITLE      = 3
CP_STATUS     = 4
CP_SELECTED   = 5
CP_BORDER     = 6
CP_CHAIN_HDR  = 7
CP_DIM        = 8
CP_USER_CHAIN = 9   # green -- user-defined chains in left panel

# Status message level color pairs
CP_INFO  = 10   # info: white on dark blue (256) / white on blue (8)
CP_WARN  = 11   # warn: black on yellow
CP_ERROR = 12   # error: white on red (bright in 256 mode)

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class FilterRule:
    id:       int = 0
    chain:    str = "INPUT"
    proto:    str = "ANY"
    dport:    str = ""          # destination port / range
    sport:    str = ""          # source port / range
    src_ip:   str = ""
    dst_ip:   str = ""
    in_iface: str = ""
    out_iface:str = ""
    state:    str = "ANY"
    action:   str = "ACCEPT"
    comment:  str = ""
    position: int = 0

@dataclass
class NatRule:
    id:         int = 0
    chain:      str = "NAT PREROUTING"
    proto:      str = "ANY"
    src_ip:     str = ""
    dst_ip:     str = ""
    dport:      str = ""
    nat_action: str = "DNAT"
    to_dest:    str = ""        # to-destination for DNAT/SNAT
    comment:    str = ""
    position:   int = 0

@dataclass
class ChainPolicy:
    chain:  str = "INPUT"
    policy: str = "ACCEPT"

@dataclass
class UserChain:
    id:    int = 0
    name:  str = ""
    table: str = "filter"   # filter | nat | mangle

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

class DB:
    def __init__(self, path: str):
        self.path = path
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self):
        c = self.conn
        c.execute("""
            CREATE TABLE IF NOT EXISTS configs (
                id   INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS chain_policies (
                config_id INTEGER,
                chain     TEXT,
                policy    TEXT DEFAULT 'ACCEPT',
                PRIMARY KEY (config_id, chain),
                FOREIGN KEY (config_id) REFERENCES configs(id)
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS filter_rules (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                config_id INTEGER,
                chain     TEXT,
                proto     TEXT DEFAULT 'ANY',
                dport     TEXT DEFAULT '',
                sport     TEXT DEFAULT '',
                src_ip    TEXT DEFAULT '',
                dst_ip    TEXT DEFAULT '',
                in_iface  TEXT DEFAULT '',
                out_iface TEXT DEFAULT '',
                state     TEXT DEFAULT 'ANY',
                action    TEXT DEFAULT 'ACCEPT',
                comment   TEXT DEFAULT '',
                position  INTEGER DEFAULT 0,
                FOREIGN KEY (config_id) REFERENCES configs(id)
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS nat_rules (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                config_id  INTEGER,
                chain      TEXT,
                proto      TEXT DEFAULT 'ANY',
                src_ip     TEXT DEFAULT '',
                dst_ip     TEXT DEFAULT '',
                dport      TEXT DEFAULT '',
                nat_action TEXT DEFAULT 'DNAT',
                to_dest    TEXT DEFAULT '',
                comment    TEXT DEFAULT '',
                position   INTEGER DEFAULT 0,
                FOREIGN KEY (config_id) REFERENCES configs(id)
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS user_chains (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                config_id  INTEGER,
                name       TEXT,
                table_name TEXT DEFAULT 'filter',
                UNIQUE (config_id, name),
                FOREIGN KEY (config_id) REFERENCES configs(id)
            )
        """)
        c.commit()

    def list_configs(self):
        return [r["name"] for r in self.conn.execute("SELECT name FROM configs ORDER BY name")]

    def config_id(self, name: str) -> Optional[int]:
        r = self.conn.execute("SELECT id FROM configs WHERE name=?", (name,)).fetchone()
        return r["id"] if r else None

    def create_config(self, name: str) -> int:
        self.conn.execute("INSERT INTO configs (name) VALUES (?)", (name,))
        self.conn.commit()
        cid = self.config_id(name)
        # default policies
        for ch in POLICY_CHAINS:
            self.conn.execute(
                "INSERT OR IGNORE INTO chain_policies (config_id,chain,policy) VALUES (?,?,?)",
                (cid, ch, "ACCEPT"))
        self.conn.commit()
        return cid

    def delete_config(self, name: str):
        cid = self.config_id(name)
        if cid is None:
            return
        self.conn.execute("DELETE FROM filter_rules WHERE config_id=?", (cid,))
        self.conn.execute("DELETE FROM nat_rules WHERE config_id=?", (cid,))
        self.conn.execute("DELETE FROM chain_policies WHERE config_id=?", (cid,))
        self.conn.execute("DELETE FROM configs WHERE id=?", (cid,))
        self.conn.commit()

    def load_policies(self, cid: int) -> dict:
        rows = self.conn.execute(
            "SELECT chain,policy FROM chain_policies WHERE config_id=?", (cid,))
        result = {ch: "ACCEPT" for ch in POLICY_CHAINS}
        for r in rows:
            result[r["chain"]] = r["policy"]
        return result

    def save_policy(self, cid: int, chain: str, policy: str):
        self.conn.execute(
            "INSERT OR REPLACE INTO chain_policies (config_id,chain,policy) VALUES (?,?,?)",
            (cid, chain, policy))
        self.conn.commit()

    def load_filter_rules(self, cid: int, chain: str) -> list:
        rows = self.conn.execute(
            "SELECT * FROM filter_rules WHERE config_id=? AND chain=? ORDER BY position",
            (cid, chain)).fetchall()
        result = []
        for r in rows:
            result.append(FilterRule(
                id=r["id"], chain=r["chain"], proto=r["proto"],
                dport=r["dport"], sport=r["sport"], src_ip=r["src_ip"],
                dst_ip=r["dst_ip"], in_iface=r["in_iface"], out_iface=r["out_iface"],
                state=r["state"], action=r["action"], comment=r["comment"],
                position=r["position"]))
        return result

    def load_nat_rules(self, cid: int, chain: str) -> list:
        rows = self.conn.execute(
            "SELECT * FROM nat_rules WHERE config_id=? AND chain=? ORDER BY position",
            (cid, chain)).fetchall()
        result = []
        for r in rows:
            result.append(NatRule(
                id=r["id"], chain=r["chain"], proto=r["proto"],
                src_ip=r["src_ip"], dst_ip=r["dst_ip"], dport=r["dport"],
                nat_action=r["nat_action"], to_dest=r["to_dest"],
                comment=r["comment"], position=r["position"]))
        return result

    def insert_filter_rule(self, cid: int, rule: FilterRule):
        self.conn.execute(
            """INSERT INTO filter_rules
               (config_id,chain,proto,dport,sport,src_ip,dst_ip,in_iface,out_iface,state,action,comment,position)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (cid, rule.chain, rule.proto, rule.dport, rule.sport, rule.src_ip,
             rule.dst_ip, rule.in_iface, rule.out_iface, rule.state, rule.action,
             rule.comment, rule.position))
        self.conn.commit()

    def insert_nat_rule(self, cid: int, rule: NatRule):
        self.conn.execute(
            """INSERT INTO nat_rules
               (config_id,chain,proto,src_ip,dst_ip,dport,nat_action,to_dest,comment,position)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (cid, rule.chain, rule.proto, rule.src_ip, rule.dst_ip,
             rule.dport, rule.nat_action, rule.to_dest, rule.comment, rule.position))
        self.conn.commit()

    def delete_filter_rule(self, rule_id: int):
        self.conn.execute("DELETE FROM filter_rules WHERE id=?", (rule_id,))
        self.conn.commit()

    def delete_nat_rule(self, rule_id: int):
        self.conn.execute("DELETE FROM nat_rules WHERE id=?", (rule_id,))
        self.conn.commit()

    def reorder_filter_rules(self, cid: int, chain: str, ordered_ids: list):
        for pos, rid in enumerate(ordered_ids):
            self.conn.execute(
                "UPDATE filter_rules SET position=? WHERE id=? AND config_id=? AND chain=?",
                (pos, rid, cid, chain))
        self.conn.commit()

    def reorder_nat_rules(self, cid: int, chain: str, ordered_ids: list):
        for pos, rid in enumerate(ordered_ids):
            self.conn.execute(
                "UPDATE nat_rules SET position=? WHERE id=? AND config_id=? AND chain=?",
                (pos, rid, cid, chain))
        self.conn.commit()

    def load_user_chains(self, cid: int) -> list:
        rows = self.conn.execute(
            "SELECT id,name,table_name FROM user_chains WHERE config_id=? ORDER BY table_name,name",
            (cid,)).fetchall()
        return [UserChain(id=r["id"], name=r["name"], table=r["table_name"]) for r in rows]

    def add_user_chain(self, cid: int, name: str, table: str) -> Optional[int]:
        try:
            self.conn.execute(
                "INSERT INTO user_chains (config_id,name,table_name) VALUES (?,?,?)",
                (cid, name, table))
            self.conn.commit()
            r = self.conn.execute(
                "SELECT id FROM user_chains WHERE config_id=? AND name=?", (cid, name)).fetchone()
            return r["id"] if r else None
        except sqlite3.IntegrityError:
            return None

    def delete_user_chain(self, cid: int, name: str):
        self.conn.execute(
            "DELETE FROM user_chains WHERE config_id=? AND name=?", (cid, name))
        # also delete all rules belonging to this user chain
        self.conn.execute(
            "DELETE FROM filter_rules WHERE config_id=? AND chain=?", (cid, name))
        self.conn.commit()

    def close(self):
        self.conn.close()

# ---------------------------------------------------------------------------
# nftables code generator
# ---------------------------------------------------------------------------

def _proto_expr(proto: str) -> str:
    if not proto or proto == "ANY":
        return ""
    return proto.lower() + " "

def _port_expr(proto: str, dport: str, sport: str) -> str:
    parts = []
    p = proto.lower() if proto and proto != "ANY" else ""
    if dport and p in ("tcp","udp","sctp"):
        parts.append(f"{p} dport {{{dport}}}" if "," in dport else f"{p} dport {dport}")
    if sport and p in ("tcp","udp","sctp"):
        parts.append(f"{p} sport {{{sport}}}" if "," in sport else f"{p} sport {sport}")
    return " ".join(parts)

def _state_expr(state: str) -> str:
    if not state or state == "ANY":
        return ""
    states = [s.strip().lower() for s in state.split(",")]
    return f"ct state {{{','.join(states)}}}"

def _iface_expr(in_iface: str, out_iface: str) -> str:
    parts = []
    if in_iface:
        parts.append(f"iifname {in_iface}")
    if out_iface:
        parts.append(f"oifname {out_iface}")
    return " ".join(parts)

def _ip_expr(src_ip: str, dst_ip: str) -> str:
    parts = []
    if src_ip:
        parts.append(f"ip saddr {src_ip}")
    if dst_ip:
        parts.append(f"ip daddr {dst_ip}")
    return " ".join(parts)

def _action_expr(action: str) -> str:
    mapping = {
        "ACCEPT":     "accept",
        "ALLOW":      "accept",       # legacy alias -- old saved configs
        "DROP":       "drop",
        "REJECT":     "reject",
        "LOG":        "log",
        "LOG,ACCEPT": "log accept",
        "LOG,ALLOW":  "log accept",   # legacy alias
        "LOG,DROP":   "log drop",
        "LOG,REJECT": "log reject",
    }
    upper = action.upper()
    if upper in mapping:
        return mapping[upper]
    # user chain jump: action stored as "-> CHAINNAME"
    if action.startswith("-> "):
        return f"jump {action[3:]}"
    # fallback: treat as a jump target directly
    return f"jump {action}"

def _filter_rule_nft(rule) -> str:
    parts = []
    ip_e = _ip_expr(rule.src_ip, rule.dst_ip)
    if ip_e:
        parts.append(ip_e)
    iface_e = _iface_expr(rule.in_iface, rule.out_iface)
    if iface_e:
        parts.append(iface_e)
    if rule.proto and rule.proto != "ANY":
        parts.append(f"meta l4proto {rule.proto.lower()}")
    port_e = _port_expr(rule.proto, rule.dport, rule.sport)
    if port_e:
        parts.append(port_e)
    state_e = _state_expr(rule.state)
    if state_e:
        parts.append(state_e)
    action_e = _action_expr(rule.action)
    comment = f" comment \"{rule.comment}\"" if rule.comment else ""
    expr = " ".join(parts) if parts else ""
    return f"{expr} {action_e}{comment}".strip()

def _nat_rule_nft(rule) -> str:
    parts = []
    ip_e = _ip_expr(rule.src_ip, rule.dst_ip)
    if ip_e:
        parts.append(ip_e)
    if rule.proto and rule.proto != "ANY":
        parts.append(f"meta l4proto {rule.proto.lower()}")
    port_e = _port_expr(rule.proto, rule.dport, "")
    if port_e:
        parts.append(port_e)
    action_e = _nat_action_expr(rule.nat_action, rule.to_dest)
    comment = f" comment \"{rule.comment}\"" if rule.comment else ""
    expr = " ".join(parts) if parts else ""
    return f"{expr} {action_e}{comment}".strip()

def _nat_action_expr(nat_action: str, to_dest: str) -> str:
    a = nat_action.upper()
    if a == "MASQUERADE":
        return "masquerade"
    elif a == "DNAT":
        return f"dnat to {to_dest}" if to_dest else "dnat"
    elif a == "SNAT":
        return f"snat to {to_dest}" if to_dest else "snat"
    return "masquerade"

def _nft_chain_name(chain: str) -> tuple:
    """Return (table, chain_name) for nftables."""
    if chain == "MANGLE":
        return ("mangle", "prerouting")
    if chain.startswith("NAT "):
        sub = chain[4:].lower()
        return ("nat", sub)
    return ("filter", chain.lower())

def _policy_nft(policy: str) -> str:
    return policy.lower()

def generate_nft_script(config_name: str, policies: dict,
                        filter_rules_by_chain: dict, nat_rules_by_chain: dict,
                        user_chains: list = None) -> str:
    if user_chains is None:
        user_chains = []
    lines = []
    lines.append(f"#!/usr/sbin/nft -f")
    lines.append(f"# Generated by nftpost {APP_VERSION} -- config: {config_name}")
    lines.append("")
    lines.append("# Flush only nftpost-managed tables (preserves iptables-nft rules)")
    lines.append("# Targeted flushes instead of 'flush ruleset' which would wipe iptables-nft")
    lines.append("delete table inet filter 2>/dev/null || true")
    lines.append("delete table ip nat 2>/dev/null || true")
    lines.append("delete table ip mangle 2>/dev/null || true")
    lines.append("")

    # partition user chains by table
    uc_filter = [uc for uc in user_chains if uc.table == "filter"]
    uc_nat    = [uc for uc in user_chains if uc.table == "nat"]
    uc_mangle = [uc for uc in user_chains if uc.table == "mangle"]

    # filter table
    lines.append("table inet filter {")
    for chain in FILTER_CHAINS:
        policy = policies.get(chain, "accept").lower()
        lines.append(f"    chain {chain.lower()} {{")
        lines.append(f"        type filter hook {chain.lower()} priority 0; policy {policy};")
        for rule in filter_rules_by_chain.get(chain, []):
            lines.append("        " + _filter_rule_nft(rule))
        lines.append("    }")
    # user chains in filter table
    for uc in uc_filter:
        lines.append(f"    chain {uc.name} {{")
        for rule in filter_rules_by_chain.get(uc.name, []):
            lines.append("        " + _filter_rule_nft(rule))
        lines.append("    }")
    lines.append("}")
    lines.append("")

    # nat table
    nat_chains_used = [c for c in NAT_CHAINS if nat_rules_by_chain.get(c)]
    if nat_chains_used or uc_nat:
        lines.append("table ip nat {")
        hook_map = {
            "NAT PREROUTING":  ("prerouting",  "dstnat",  -100),
            "NAT INPUT":       ("input",        "filter",   100),
            "NAT OUTPUT":      ("output",       "dstnat",  -100),
            "NAT POSTROUTING": ("postrouting",  "srcnat",   100),
        }
        for chain in NAT_CHAINS:
            if not nat_rules_by_chain.get(chain):
                continue
            hook, nat_type, prio = hook_map[chain]
            lines.append(f"    chain {hook} {{")
            lines.append(f"        type nat hook {hook} priority {prio};")
            for rule in nat_rules_by_chain[chain]:
                lines.append("        " + _nat_rule_nft(rule))
            lines.append("    }")
        for uc in uc_nat:
            lines.append(f"    chain {uc.name} {{")
            for rule in nat_rules_by_chain.get(uc.name, []):
                lines.append("        " + _nat_rule_nft(rule))
            lines.append("    }")
        lines.append("}")
        lines.append("")

    # mangle table
    mangle_rules = filter_rules_by_chain.get("MANGLE", [])
    if mangle_rules or uc_mangle:
        lines.append("table ip mangle {")
        if mangle_rules:
            lines.append("    chain prerouting {")
            lines.append("        type filter hook prerouting priority mangle;")
            for rule in mangle_rules:
                lines.append("        " + _filter_rule_nft(rule))
            lines.append("    }")
        for uc in uc_mangle:
            lines.append(f"    chain {uc.name} {{")
            for rule in filter_rules_by_chain.get(uc.name, []):
                lines.append("        " + _filter_rule_nft(rule))
            lines.append("    }")
        lines.append("}")

    return "\n".join(lines) + "\n"

def _ipt_filter_rule(rule, chain: str) -> str:
    """Render a FilterRule as an iptables-save rule line."""
    parts = ["-A", chain]

    if rule.in_iface:
        parts += ["-i", rule.in_iface]
    if rule.out_iface:
        parts += ["-o", rule.out_iface]
    if rule.proto and rule.proto != "ANY":
        parts += ["-p", rule.proto.lower()]
    if rule.src_ip:
        parts += ["-s", rule.src_ip]
    if rule.dst_ip:
        parts += ["-d", rule.dst_ip]
    if rule.dport and rule.proto and rule.proto.upper() in ("TCP", "UDP", "SCTP"):
        parts += ["--dport", rule.dport]
    if rule.sport and rule.proto and rule.proto.upper() in ("TCP", "UDP", "SCTP"):
        parts += ["--sport", rule.sport]

    # state matching
    if rule.state and rule.state != "ANY":
        states = ",".join(s.strip().upper() for s in rule.state.split(","))
        parts += ["-m", "conntrack", "--ctstate", states]

    # comment
    if rule.comment:
        parts += ["-m", "comment", "--comment", f'"{rule.comment}"']

    # jump target
    action = rule.action.upper()
    ipt_action_map = {
        "ACCEPT":     "ACCEPT",
        "ALLOW":      "ACCEPT",
        "DROP":       "DROP",
        "REJECT":     "REJECT",
        "LOG":        "LOG",
        "LOG,ACCEPT": "LOG",   # LOG then ACCEPT needs two rules; emit LOG here
        "LOG,DROP":   "LOG",
        "LOG,REJECT": "LOG",
    }
    if action in ipt_action_map:
        parts += ["-j", ipt_action_map[action]]
    elif action.startswith("-> "):
        parts += ["-j", action[3:]]
    else:
        parts += ["-j", action]

    rule_line = " ".join(parts)

    # LOG,* compound actions need a follow-up rule with the terminal action
    compound = {
        "LOG,ACCEPT": "ACCEPT",
        "LOG,DROP":   "DROP",
        "LOG,REJECT": "REJECT",
    }
    if action in compound:
        parts2 = list(parts)
        # replace -j LOG with -j <terminal>
        j_idx = parts2.index("-j")
        parts2[j_idx + 1] = compound[action]
        rule_line += "\n" + " ".join(parts2)

    return rule_line


def _ipt_nat_rule(rule, chain: str) -> str:
    """Render a NatRule as an iptables-save rule line."""
    # map nftpost NAT chain names to iptables chain names
    chain_map = {
        "NAT PREROUTING":  "PREROUTING",
        "NAT INPUT":       "INPUT",
        "NAT OUTPUT":      "OUTPUT",
        "NAT POSTROUTING": "POSTROUTING",
    }
    ipt_chain = chain_map.get(chain, chain)
    parts = ["-A", ipt_chain]

    if rule.proto and rule.proto != "ANY":
        parts += ["-p", rule.proto.lower()]
    if rule.src_ip:
        parts += ["-s", rule.src_ip]
    if rule.dst_ip:
        parts += ["-d", rule.dst_ip]
    if rule.dport and rule.proto and rule.proto.upper() in ("TCP", "UDP", "SCTP"):
        parts += ["--dport", rule.dport]
    if rule.comment:
        parts += ["-m", "comment", "--comment", f'"{rule.comment}"']

    action = rule.nat_action.upper()
    if action == "MASQUERADE":
        parts += ["-j", "MASQUERADE"]
    elif action == "DNAT":
        parts += ["-j", "DNAT"]
        if rule.to_dest:
            parts += ["--to-destination", rule.to_dest]
    elif action == "SNAT":
        parts += ["-j", "SNAT"]
        if rule.to_dest:
            parts += ["--to-source", rule.to_dest]

    return " ".join(parts)


def generate_ipt_save(config_name: str, policies: dict,
                      filter_rules_by_chain: dict, nat_rules_by_chain: dict,
                      user_chains: list = None) -> str:
    """Generate an iptables-save compatible restore file."""
    if user_chains is None:
        user_chains = []

    uc_filter = [uc for uc in user_chains if uc.table == "filter"]
    uc_nat    = [uc for uc in user_chains if uc.table == "nat"]
    uc_mangle = [uc for uc in user_chains if uc.table == "mangle"]

    lines = []
    lines.append(f"# Generated by nftpost {APP_VERSION} -- config: {config_name}")
    lines.append(f"# iptables-save format -- restore with: iptables-restore < <file>")
    lines.append("")

    # ----- *filter -----
    lines.append("*filter")
    # built-in chain policies
    for chain in FILTER_CHAINS:
        policy = policies.get(chain, "ACCEPT").upper()
        lines.append(f":{chain} {policy} [0:0]")
    # user chain declarations (no policy)
    for uc in uc_filter:
        lines.append(f":{uc.name} - [0:0]")
    # rules
    for chain in FILTER_CHAINS:
        for rule in filter_rules_by_chain.get(chain, []):
            lines.append(_ipt_filter_rule(rule, chain))
    for uc in uc_filter:
        for rule in filter_rules_by_chain.get(uc.name, []):
            lines.append(_ipt_filter_rule(rule, uc.name))
    lines.append("COMMIT")
    lines.append("")

    # ----- *nat -----
    lines.append("*nat")
    nat_chain_map = {
        "NAT PREROUTING":  "PREROUTING",
        "NAT INPUT":       "INPUT",
        "NAT OUTPUT":      "OUTPUT",
        "NAT POSTROUTING": "POSTROUTING",
    }
    for nft_chain, ipt_chain in nat_chain_map.items():
        lines.append(f":{ipt_chain} ACCEPT [0:0]")
    for uc in uc_nat:
        lines.append(f":{uc.name} - [0:0]")
    for nft_chain in NAT_CHAINS:
        ipt_chain = nat_chain_map[nft_chain]
        for rule in nat_rules_by_chain.get(nft_chain, []):
            lines.append(_ipt_nat_rule(rule, nft_chain))
    for uc in uc_nat:
        for rule in nat_rules_by_chain.get(uc.name, []):
            lines.append(_ipt_nat_rule(rule, uc.name))
    lines.append("COMMIT")
    lines.append("")

    # ----- *mangle -----
    lines.append("*mangle")
    for chain in ["PREROUTING", "INPUT", "FORWARD", "OUTPUT", "POSTROUTING"]:
        lines.append(f":{chain} ACCEPT [0:0]")
    for uc in uc_mangle:
        lines.append(f":{uc.name} - [0:0]")
    for rule in filter_rules_by_chain.get("MANGLE", []):
        lines.append(_ipt_filter_rule(rule, "PREROUTING"))
    for uc in uc_mangle:
        for rule in filter_rules_by_chain.get(uc.name, []):
            lines.append(_ipt_filter_rule(rule, uc.name))
    lines.append("COMMIT")
    lines.append("")

    return "\n".join(lines) + "\n"

def safe_addstr(win, y, x, text, attr=0):
    try:
        win.addstr(y, x, text, attr)
    except curses.error:
        pass

def center_text(win, y, text, attr=0, width=None):
    if width is None:
        _, width = win.getmaxyx()
    x = max(0, (width - len(text)) // 2)
    safe_addstr(win, y, x, text, attr)

def draw_box(win, y, x, h, w, attr=0):
    try:
        win.attron(attr)
        win.border()
        win.attroff(attr)
    except curses.error:
        pass

def _col(value: str, width: int) -> str:
    """Fit value into exactly `width` chars, truncating with ... if needed."""
    if not value:
        value = "-"
    if len(value) > width:
        return value[:width - 3] + "..." if width > 3 else value[:width]
    return f"{value:<{width}}"

def _fmt_addr(ip: str, iface: str) -> str:
    """Combine IP and interface into a single display value for SRC/DST columns."""
    if ip and iface:
        return f"{iface}|{ip}"
    return ip or iface or "-"

def rule_summary_filter(rule: FilterRule, width: int = 0) -> str:
    proto   = rule.proto   or "ANY"
    dport   = rule.dport   or "-"
    src     = _fmt_addr(rule.src_ip, rule.in_iface)
    dst     = _fmt_addr(rule.dst_ip, rule.out_iface)
    state   = rule.state   or "ANY"
    action  = rule.action  or "-"
    comment = rule.comment or ""
    cols = (
        _col(proto,  COL_PROTO)  + " " +
        _col(dport,  COL_DPORT)  + " " +
        _col(src,    COL_SRC)    + " " +
        _col(dst,    COL_DST)    + " " +
        _col(state,  COL_STATE)  + " " +
        _col(action, COL_ACTION) + " " +
        _col(comment, COL_COMMENT)
    )
    return cols if not width else cols[:width]

def rule_summary_nat(rule: NatRule, width: int = 0) -> str:
    proto   = rule.proto      or "ANY"
    dport   = rule.dport      or "-"
    src     = rule.src_ip     or "-"
    dst     = rule.dst_ip     or "-"
    action  = rule.nat_action or "-"
    to_d    = rule.to_dest    or "-"
    comment = rule.comment    or ""
    cols = (
        _col(proto,   COL_PROTO)  + " " +
        _col(dport,   COL_DPORT)  + " " +
        _col(src,     COL_SRC)    + " " +
        _col(dst,     COL_DST)    + " " +
        _col(action,  COL_ACTION) + " " +
        _col(to_d,    COL_TODEST) + " " +
        _col(comment, COL_COMMENT)
    )
    return cols if not width else cols[:width]

# ---------------------------------------------------------------------------
# Dialog: text input with label
# ---------------------------------------------------------------------------

def input_dialog(stdscr, title: str, prompt: str, default: str = "") -> Optional[str]:
    """Single-line text input dialog. Returns None on Esc/Cancel."""
    sh, sw = stdscr.getmaxyx()
    HINT = "Enter: confirm   Esc: cancel"
    w = _dialog_width(sw, title, prompt, HINT, min_w=40)
    h = 7
    y = (sh - h) // 2
    x = (sw - w) // 2
    win = curses.newwin(h, w, y, x)
    win.keypad(True)
    win.attron(curses.color_pair(CP_BORDER))
    win.box()
    win.attroff(curses.color_pair(CP_BORDER))
    center_text(win, 0, f" {title} ", curses.color_pair(CP_TITLE) | curses.A_BOLD, w)
    safe_addstr(win, 2, 2, prompt, curses.color_pair(CP_NORMAL))
    safe_addstr(win, 4, 2, HINT, curses.color_pair(CP_DIM))

    buf = list(default)
    cur = len(buf)
    input_w = w - 4
    input_x = 2
    input_y = 3

    while True:
        # draw input field
        display = "".join(buf)
        field_str = (display + " " * input_w)[:input_w]
        safe_addstr(win, input_y, input_x, field_str, curses.color_pair(CP_HIGHLIGHT))
        win.move(input_y, input_x + min(cur, input_w - 1))
        win.refresh()
        key = win.getch()
        if key in (27,):  # Esc
            return None
        elif key in (10, 13):  # Enter
            return "".join(buf)
        elif key in (curses.KEY_BACKSPACE, 127, 8):
            if cur > 0:
                buf.pop(cur - 1)
                cur -= 1
        elif key == curses.KEY_LEFT:
            cur = max(0, cur - 1)
        elif key == curses.KEY_RIGHT:
            cur = min(len(buf), cur + 1)
        elif key == curses.KEY_HOME:
            cur = 0
        elif key == curses.KEY_END:
            cur = len(buf)
        elif key == curses.KEY_DC:
            if cur < len(buf):
                buf.pop(cur)
        elif 32 <= key < 127:
            buf.insert(cur, chr(key))
            cur += 1

# ---------------------------------------------------------------------------
# Dialog: pick from a list
# ---------------------------------------------------------------------------

def _dialog_width(sw: int, *text_sources, min_w: int = 24, padding: int = 6) -> int:
    """
    Compute a dialog width that fits all supplied strings plus box padding,
    capped at the terminal width.  Pass every string the dialog will display
    (title, hint lines, option labels, prompt text, etc.) as positional args;
    they may be plain strings or lists/tuples of strings.
    """
    widest = min_w
    for src in text_sources:
        items = src if isinstance(src, (list, tuple)) else [src]
        for s in items:
            widest = max(widest, len(str(s)))
    return min(widest + padding, sw - 4)

def pick_dialog(stdscr, title: str, options: list, current: str = "") -> Optional[str]:
    sh, sw = stdscr.getmaxyx()
    HINT = "Enter:select  Esc:cancel"
    w = _dialog_width(sw, title, options, HINT)
    h = min(len(options) + 4, sh - 4)
    y = (sh - h) // 2
    x = (sw - w) // 2
    win = curses.newwin(h, w, y, x)
    win.keypad(True)

    try:
        sel = options.index(current)
    except ValueError:
        sel = 0

    offset = 0
    visible = h - 4

    while True:
        win.erase()
        win.attron(curses.color_pair(CP_BORDER))
        win.box()
        win.attroff(curses.color_pair(CP_BORDER))
        center_text(win, 0, f" {title} ", curses.color_pair(CP_TITLE) | curses.A_BOLD, w)
        safe_addstr(win, h - 2, 2, HINT, curses.color_pair(CP_DIM))

        if sel < offset:
            offset = sel
        elif sel >= offset + visible:
            offset = sel - visible + 1

        for i in range(visible):
            idx = i + offset
            if idx >= len(options):
                break
            label = options[idx][:w - 4]
            attr = curses.color_pair(CP_HIGHLIGHT) | curses.A_BOLD if idx == sel else curses.color_pair(CP_NORMAL)
            safe_addstr(win, 1 + i, 2, f" {label:<{w-5}}", attr)

        win.refresh()
        key = win.getch()
        if key == 27:
            return None
        elif key in (10, 13):
            return options[sel]
        elif key == curses.KEY_UP:
            sel = max(0, sel - 1)
        elif key == curses.KEY_DOWN:
            sel = min(len(options) - 1, sel + 1)

# ---------------------------------------------------------------------------
# Dialog: confirm yes/no
# ---------------------------------------------------------------------------

def confirm_dialog(stdscr, title: str, msg: str) -> bool:
    sh, sw = stdscr.getmaxyx()
    HINT = "y: yes   n/Esc: no"
    w = _dialog_width(sw, title, msg, HINT)
    h = 7
    y = (sh - h) // 2
    x = (sw - w) // 2
    win = curses.newwin(h, w, y, x)
    win.keypad(True)
    win.attron(curses.color_pair(CP_BORDER))
    win.box()
    win.attroff(curses.color_pair(CP_BORDER))
    center_text(win, 0, f" {title} ", curses.color_pair(CP_TITLE) | curses.A_BOLD, w)
    center_text(win, 2, msg, curses.color_pair(CP_NORMAL), w)
    center_text(win, 4, HINT, curses.color_pair(CP_DIM), w)
    win.refresh()
    while True:
        key = win.getch()
        if key in (ord('y'), ord('Y')):
            return True
        elif key in (27, ord('n'), ord('N')):
            return False

# ---------------------------------------------------------------------------
# Dialog: message/status popup
# ---------------------------------------------------------------------------

def msg_dialog(stdscr, title: str, lines: list):
    sh, sw = stdscr.getmaxyx()
    HINT = "Press any key"
    w = _dialog_width(sw, title, lines, HINT)
    h = len(lines) + 5
    y = (sh - h) // 2
    x = (sw - w) // 2
    win = curses.newwin(h, w, y, x)
    win.keypad(True)
    win.attron(curses.color_pair(CP_BORDER))
    win.box()
    win.attroff(curses.color_pair(CP_BORDER))
    center_text(win, 0, f" {title} ", curses.color_pair(CP_TITLE) | curses.A_BOLD, w)
    for i, line in enumerate(lines):
        safe_addstr(win, 1 + i, 2, line[:w-3], curses.color_pair(CP_NORMAL))
    center_text(win, h - 2, "Press any key", curses.color_pair(CP_DIM), w)
    win.refresh()
    win.getch()

# ---------------------------------------------------------------------------
# Dialog: Turbo-C style form for filter rules
# ---------------------------------------------------------------------------

FILTER_FIELDS = [
    ("proto",     "Protocol",          VALID_PROTOS,  "pick"),
    ("dport",     "Dest Port/Range",   None,          "text"),
    ("sport",     "Src  Port/Range",   None,          "text"),
    ("src_ip",    "Source IP/CIDR",    None,          "text"),
    ("dst_ip",    "Dest IP/CIDR",      None,          "text"),
    ("in_iface",  "In Interface",      None,          "text"),
    ("out_iface", "Out Interface",     None,          "text"),
    ("state",     "State",             VALID_STATES,  "pick"),
    ("action",    "Action",            VALID_ACTIONS, "pick"),
    ("comment",   "Comment",           None,          "text"),
]

NAT_FIELDS = [
    ("proto",      "Protocol",         VALID_PROTOS,       "pick"),
    ("src_ip",     "Source IP/CIDR",   None,               "text"),
    ("dst_ip",     "Dest IP/CIDR",     None,               "text"),
    ("dport",      "Dest Port/Range",  None,               "text"),
    ("nat_action", "NAT Action",       VALID_NAT_ACTIONS,  "pick"),
    ("to_dest",    "To Destination",   None,               "text"),
    ("comment",    "Comment",          None,               "text"),
]

def _get_field_value(obj, fname):
    return getattr(obj, fname, "")

def _set_field_value(obj, fname, val):
    setattr(obj, fname, val)

def rule_form_dialog(stdscr, title: str, rule, field_defs: list) -> bool:
    """
    Turbo-C style form dialog.

    Navigation (yellow bar, cursor hidden):
      Tab / Shift-Tab / Up / Down  -- move between fields
      Enter on pick field          -- open sub-picker
      Enter on text field          -- enter input mode
      F10 / s                      -- save and close
      Esc                          -- cancel dialog

    Input mode (white input area, cursor visible):
      printable keys               -- type into field
      Left / Right / Home / End    -- move cursor within field
      Backspace / Del              -- delete characters
      Enter                        -- commit value, return to navigation
      Esc                          -- discard changes to this field, return to navigation
      Up / Down / Tab / Shift-Tab  -- commit value, move to adjacent field
    """
    sh, sw = stdscr.getmaxyx()
    n_fields = len(field_defs)
    h = n_fields + 7
    label_w = max(len(f[1]) for f in field_defs) + 2
    val_w   = min(sw - 4 - label_w - 6, 35)
    w       = label_w + val_w + 6
    w       = min(w, sw - 4)
    y = (sh - h) // 2
    x = (sw - w) // 2
    win = curses.newwin(h, w, y, x)
    win.keypad(True)

    sel      = 0      # highlighted field index
    editing  = False  # True = input mode active on current field
    edit_buf = []     # mutable copy of value being edited
    edit_cur = 0      # cursor position within edit_buf
    edit_orig = ""    # saved value before editing started (for Esc-discard)

    # value column x offset (inside win coords)
    val_x = 2 + label_w + 1   # position of '[' bracket

    def _commit():
        """Write edit_buf back to the rule object."""
        nonlocal editing
        _set_field_value(rule, field_defs[sel][0], "".join(edit_buf))
        editing = False
        curses.curs_set(0)

    def _discard():
        """Restore original value and leave input mode."""
        nonlocal editing
        _set_field_value(rule, field_defs[sel][0], edit_orig)
        editing = False
        curses.curs_set(0)

    def _start_edit():
        nonlocal editing, edit_buf, edit_cur, edit_orig
        editing   = True
        edit_orig = str(_get_field_value(rule, field_defs[sel][0]))
        edit_buf  = list(edit_orig)
        edit_cur  = len(edit_buf)
        curses.curs_set(1)

    def draw():
        win.erase()
        win.attron(curses.color_pair(CP_BORDER))
        win.box()
        win.attroff(curses.color_pair(CP_BORDER))
        center_text(win, 0, f" {title} ", curses.color_pair(CP_TITLE) | curses.A_BOLD, w)

        if editing:
            hint = "Enter:commit  Esc:discard  Arrows:commit+move"
        else:
            hint = "Tab/Arrows:move  Enter:edit/pick  F10/s:save  Esc:cancel"
        safe_addstr(win, h - 3, 2, hint[:w - 3], curses.color_pair(CP_DIM))
        safe_addstr(win, h - 2, 2, "(blank = ANY/omit)", curses.color_pair(CP_DIM))

        for i, (fname, label, opts, ftype) in enumerate(field_defs):
            row = 1 + i
            is_sel = (i == sel)

            if is_sel:
                # label: always yellow when selected
                safe_addstr(win, row, 2,
                            f"{label:<{label_w}}",
                            curses.color_pair(CP_SELECTED) | curses.A_BOLD)
                if editing:
                    # value area: white-on-black input mode
                    val = "".join(edit_buf)
                    field_str = (val + " " * val_w)[:val_w]
                    safe_addstr(win, row, val_x,
                                f"[{field_str}]",
                                curses.color_pair(CP_NORMAL) | curses.A_REVERSE)
                    # place hardware cursor
                    cur_col = val_x + 1 + min(edit_cur, val_w - 1)
                    try:
                        win.move(row, cur_col)
                    except curses.error:
                        pass
                else:
                    # value area: yellow (same bar as label)
                    val = str(_get_field_value(rule, fname))
                    field_str = (val + " " * val_w)[:val_w]
                    safe_addstr(win, row, val_x,
                                f"[{field_str}]",
                                curses.color_pair(CP_SELECTED))
            else:
                # non-selected row: plain white label, dim value
                safe_addstr(win, row, 2,
                            f"{label:<{label_w}}",
                            curses.color_pair(CP_NORMAL))
                val = str(_get_field_value(rule, fname))
                field_str = (val + " " * val_w)[:val_w]
                safe_addstr(win, row, val_x,
                            f"[{field_str}]",
                            curses.color_pair(CP_DIM))

    curses.curs_set(0)   # start with cursor off

    while True:
        draw()
        win.refresh()
        key = win.getch()

        fname, label, opts, ftype = field_defs[sel]

        # ---- input mode keys ----
        if editing:
            if key == 27:                          # Esc -- discard this field
                _discard()
            elif key in (10, 13):                 # Enter -- commit, stay on field
                _commit()
            elif key in (9, curses.KEY_DOWN):     # Tab / Down -- commit + move down
                _commit()
                sel = (sel + 1) % n_fields
            elif key in (curses.KEY_BTAB, curses.KEY_UP):  # Shift-Tab / Up -- commit + move up
                _commit()
                sel = (sel - 1) % n_fields
            elif key in (curses.KEY_BACKSPACE, 127, 8):
                if edit_cur > 0:
                    edit_buf.pop(edit_cur - 1)
                    edit_cur -= 1
            elif key == curses.KEY_LEFT:
                edit_cur = max(0, edit_cur - 1)
            elif key == curses.KEY_RIGHT:
                edit_cur = min(len(edit_buf), edit_cur + 1)
            elif key == curses.KEY_HOME:
                edit_cur = 0
            elif key == curses.KEY_END:
                edit_cur = len(edit_buf)
            elif key == curses.KEY_DC:
                if edit_cur < len(edit_buf):
                    edit_buf.pop(edit_cur)
            elif 32 <= key < 127:
                edit_buf.insert(edit_cur, chr(key))
                edit_cur += 1

        # ---- navigation mode keys ----
        else:
            if key == 27:                          # Esc -- cancel dialog
                curses.curs_set(0)
                return False

            elif key in (curses.KEY_F10, ord('s')):
                curses.curs_set(0)
                return True

            elif key in (9, curses.KEY_DOWN):
                sel = (sel + 1) % n_fields

            elif key in (curses.KEY_BTAB, curses.KEY_UP):
                sel = (sel - 1) % n_fields

            elif key in (10, 13):
                if ftype == "pick" and opts:
                    cur_val = str(_get_field_value(rule, fname))
                    chosen = pick_dialog(stdscr, label, opts, cur_val)
                    if chosen is not None:
                        _set_field_value(rule, fname, chosen)
                else:
                    _start_edit()

# ---------------------------------------------------------------------------
# Main application class
# ---------------------------------------------------------------------------

class NftpostApp:
    def __init__(self, stdscr, use_256: bool = True):
        self.stdscr = stdscr
        self.use_256 = use_256
        self.db = DB(DB_PATH)
        self.config_name: Optional[str] = None
        self.config_id: Optional[int] = None
        self.policies: dict = {ch: "ACCEPT" for ch in POLICY_CHAINS}
        # in-memory rules per chain (keyed by chain name string)
        self.filter_rules: dict = {ch: [] for ch in FILTER_CHAINS + MANGLE_CHAINS}
        self.nat_rules: dict = {ch: [] for ch in NAT_CHAINS}
        # user-defined chains (list of UserChain); rules stored in filter_rules[uc.name]
        self.user_chains: list = []
        self.selected_chain_idx = 0
        self.selected_rule_idx  = 0
        self.focus_right = False
        self.status_msg   = ""
        self.status_level = "info"   # "info" | "warn" | "error"
        self._init_colors()
        curses.curs_set(0)

    def _init_colors(self):
        curses.start_color()
        curses.use_default_colors()

        if self.use_256 and curses.COLORS >= 256:
            # 256-color palette -- richer, more distinct
            # xterm-256 color numbers used here:
            #   24  = steel blue bg for title/highlight
            #   17  = dark navy bg for info
            #   58  = olive/dark yellow bg for warn
            #   88  = dark red bg for error
            #   40  = green for user chains
            #   244 = mid-grey for dim text
            C_BG_TITLE  = 24
            C_BG_INFO   = 17
            C_BG_WARN   = 58
            C_BG_ERROR  = 88
            C_GREEN     = 40
            C_GREY      = 244
            C_CYAN      = 51
            C_YELLOW    = 220
            C_WHITE     = 255
            C_BLACK     = 16
            curses.init_pair(CP_NORMAL,     C_WHITE,   -1)
            curses.init_pair(CP_HIGHLIGHT,  C_BLACK,   C_BG_TITLE)
            curses.init_pair(CP_TITLE,      C_WHITE,   C_BG_TITLE)
            curses.init_pair(CP_STATUS,     C_BLACK,   C_GREY)
            curses.init_pair(CP_SELECTED,   C_BLACK,   C_YELLOW)
            curses.init_pair(CP_BORDER,     C_CYAN,    -1)
            curses.init_pair(CP_CHAIN_HDR,  C_YELLOW,  -1)
            curses.init_pair(CP_DIM,        C_GREY,    -1)
            curses.init_pair(CP_USER_CHAIN, C_GREEN,   -1)
            curses.init_pair(CP_INFO,       C_WHITE,   C_BG_INFO)
            curses.init_pair(CP_WARN,       C_BLACK,   C_YELLOW)
            curses.init_pair(CP_ERROR,      C_WHITE,   C_BG_ERROR)
        else:
            # 8-color fallback
            curses.init_pair(CP_NORMAL,     curses.COLOR_WHITE,   -1)
            curses.init_pair(CP_HIGHLIGHT,  curses.COLOR_BLACK,   curses.COLOR_CYAN)
            curses.init_pair(CP_TITLE,      curses.COLOR_BLACK,   curses.COLOR_CYAN)
            curses.init_pair(CP_STATUS,     curses.COLOR_BLACK,   curses.COLOR_WHITE)
            curses.init_pair(CP_SELECTED,   curses.COLOR_BLACK,   curses.COLOR_YELLOW)
            curses.init_pair(CP_BORDER,     curses.COLOR_CYAN,    -1)
            curses.init_pair(CP_CHAIN_HDR,  curses.COLOR_YELLOW,  -1)
            curses.init_pair(CP_DIM,        curses.COLOR_WHITE,   -1)
            curses.init_pair(CP_USER_CHAIN, curses.COLOR_GREEN,   -1)
            curses.init_pair(CP_INFO,       curses.COLOR_WHITE,   curses.COLOR_BLUE)
            curses.init_pair(CP_WARN,       curses.COLOR_BLACK,   curses.COLOR_YELLOW)
            curses.init_pair(CP_ERROR,      curses.COLOR_WHITE,   curses.COLOR_RED)

    def _all_chains(self) -> list:
        """Full ordered chain list: builtins then user chains."""
        return BUILTIN_CHAINS + [uc.name for uc in self.user_chains]

    @property
    def current_chain(self) -> str:
        chains = self._all_chains()
        idx = min(self.selected_chain_idx, len(chains) - 1)
        return chains[idx]

    def _rules_for_chain(self, chain: str) -> list:
        if chain in NAT_CHAINS:
            return self.nat_rules.get(chain, [])
        return self.filter_rules.get(chain, [])

    def _is_nat_chain(self, chain: str) -> bool:
        # NAT builtin chains, or user chains in the nat table
        if chain in NAT_CHAINS:
            return True
        uc = self._user_chain_obj(chain)
        return uc is not None and uc.table == "nat"

    def _user_chain_obj(self, name: str) -> Optional[UserChain]:
        for uc in self.user_chains:
            if uc.name == name:
                return uc
        return None

    def _is_user_chain(self, chain: str) -> bool:
        return self._user_chain_obj(chain) is not None

    def _available_actions(self, chain: str) -> list:
        """Return action list for picker, including jump targets for same-table user chains."""
        actions = list(VALID_ACTIONS)
        # determine table of the current chain
        if chain in FILTER_CHAINS or chain == "MANGLE":
            table = "filter" if chain != "MANGLE" else "mangle"
        elif chain in NAT_CHAINS:
            table = "nat"
        else:
            uc = self._user_chain_obj(chain)
            table = uc.table if uc else "filter"
        # add user chains from same table as jump targets
        for uc in self.user_chains:
            if uc.table == table and uc.name != chain:
                actions.append(f"-> {uc.name}")
        return actions

    def info(self, msg: str):
        self.status_msg   = msg
        self.status_level = "info"

    def warn(self, msg: str):
        self.status_msg   = f"  {msg}"
        self.status_level = "warn"

    def error(self, msg: str):
        self.status_msg   = f"  {msg}"
        self.status_level = "error"

    def _status_attr(self) -> int:
        pair = {
            "info":  CP_INFO,
            "warn":  CP_WARN,
            "error": CP_ERROR,
        }.get(self.status_level, CP_INFO)
        attr = curses.color_pair(pair) | curses.A_BOLD
        return attr

    def run(self):
        self.stdscr.keypad(True)
        while True:
            self._draw()
            key = self.stdscr.getch()
            self.status_msg = ""        # clear previous status before handling
            if not self._handle_key(key):
                break
        self.db.close()

    # -----------------------------------------------------------------------
    # Drawing
    # -----------------------------------------------------------------------

    def _draw(self):
        sh, sw = self.stdscr.getmaxyx()
        self.stdscr.erase()

        # title bar
        title = f" nftpost {APP_VERSION}"
        if self.config_name:
            title += f" -- {self.config_name}"
        title_pad = title + " " * (sw - len(title))
        safe_addstr(self.stdscr, 0, 0, title_pad[:sw],
                    curses.color_pair(CP_TITLE) | curses.A_BOLD)

        # status bar
        status_bar = (
            " q:quit  s:save  l:load  i:insert  a:add  e:edit  d:del rule  "
            "o:order  p:policy  n:new chain  x:del chain  g:generate"
        )
        status_pad = (status_bar + " " * sw)[:sw]
        safe_addstr(self.stdscr, sh - 1, 0, status_pad,
                    curses.color_pair(CP_STATUS))

        # status message line
        if self.status_msg:
            msg = self.status_msg[:sw]
            safe_addstr(self.stdscr, sh - 2, 0,
                        (msg + " " * sw)[:sw],
                        self._status_attr())

        # main area
        main_y = 1
        main_h = sh - 3 if self.status_msg else sh - 2
        left_w = 22
        right_x = left_w + 2
        right_w = sw - right_x - 1

        # outer border
        try:
            outer = curses.newwin(main_h, sw, main_y, 0)
            outer.attron(curses.color_pair(CP_BORDER))
            outer.box()
            outer.attroff(curses.color_pair(CP_BORDER))
            outer.refresh()
        except curses.error:
            pass

        # vertical divider
        for row in range(main_y + 1, main_y + main_h - 1):
            safe_addstr(self.stdscr, row, left_w + 1, "|",
                        curses.color_pair(CP_BORDER))

        # left panel: chain list
        self._draw_chain_list(main_y + 1, 1, main_h - 2, left_w)

        # right panel: rule list
        self._draw_rule_list(main_y + 1, right_x, main_h - 2, right_w)

        self.stdscr.refresh()

    def _draw_chain_list(self, y, x, h, w):
        chains = self._all_chains()
        n_builtin = len(BUILTIN_CHAINS)
        row = 0
        for i, chain in enumerate(chains):
            if row >= h:
                break
            # draw separator before first user chain
            if i == n_builtin and self.user_chains:
                sep = ("-" * (w - 2))[:w - 2]
                safe_addstr(self.stdscr, y + row, x,
                            f" {sep}", curses.color_pair(CP_DIM))
                row += 1
                if row >= h:
                    break
            is_sel = (i == self.selected_chain_idx)
            is_user = (i >= n_builtin)
            if is_sel and not self.focus_right:
                attr = curses.color_pair(CP_HIGHLIGHT) | curses.A_BOLD
            elif is_sel:
                attr = curses.color_pair(CP_NORMAL) | curses.A_BOLD
            elif is_user:
                attr = curses.color_pair(CP_USER_CHAIN)
            else:
                attr = curses.color_pair(CP_NORMAL)
            # user chains shown with table prefix in dim
            if is_user:
                uc = self._user_chain_obj(chain)
                prefix = f"[{uc.table[0]}]" if uc else "   "
                label = f"{prefix} {chain}"[:w - 2]
            else:
                label = chain[:w - 2]
            safe_addstr(self.stdscr, y + row, x, f" {label:<{w-2}}", attr)
            row += 1

    def _draw_rule_list(self, y, x, h, w):
        chain = self.current_chain
        rules = self._rules_for_chain(chain)

        # chain header with policy if applicable
        if chain in POLICY_CHAINS:
            policy = self.policies.get(chain, "ACCEPT")
            header = f"{chain}: {policy}"
        else:
            header = chain

        safe_addstr(self.stdscr, y, x,
                    f" {header:<{w-2}}",
                    curses.color_pair(CP_CHAIN_HDR) | curses.A_BOLD)

        # column headers -- built from the same constants as the data rows
        num_pad = " " * (COL_NUM + 1)   # "NN. " + leading space
        if self._is_nat_chain(chain):
            col_hdr = (
                num_pad +
                _col("PROTO",   COL_PROTO)  + " " +
                _col("DPORT",   COL_DPORT)  + " " +
                _col("SRC",     COL_SRC)    + " " +
                _col("DST",     COL_DST)    + " " +
                _col("ACTION",  COL_ACTION) + " " +
                _col("TO-DEST", COL_TODEST) + " " +
                "COMMENT"
            )
        else:
            col_hdr = (
                num_pad +
                _col("PROTO",   COL_PROTO)  + " " +
                _col("DPORT",   COL_DPORT)  + " " +
                _col("SRC",     COL_SRC)    + " " +
                _col("DST",     COL_DST)    + " " +
                _col("STATE",   COL_STATE)  + " " +
                _col("ACTION",  COL_ACTION) + " " +
                "COMMENT"
            )
        safe_addstr(self.stdscr, y + 1, x,
                    col_hdr[:w],
                    curses.color_pair(CP_DIM) | curses.A_UNDERLINE)

        list_y = y + 2
        list_h = h - 2

        if not rules:
            safe_addstr(self.stdscr, list_y, x,
                        " (no rules)",
                        curses.color_pair(CP_DIM))
            return

        # scroll window
        if self.selected_rule_idx >= list_h:
            offset = self.selected_rule_idx - list_h + 1
        else:
            offset = 0

        for i in range(list_h):
            idx = i + offset
            if idx >= len(rules):
                break
            rule = rules[idx]
            is_sel = (idx == self.selected_rule_idx) and self.focus_right
            attr = curses.color_pair(CP_HIGHLIGHT) | curses.A_BOLD if is_sel else curses.color_pair(CP_NORMAL)
            num = f"{idx+1:>2}. "
            if self._is_nat_chain(chain):
                text = rule_summary_nat(rule)
            else:
                text = rule_summary_filter(rule)
            row_str = (" " + num + text)[:w]
            # pad to full panel width so highlight bar extends across
            row_str = f"{row_str:<{w}}"[:w]
            safe_addstr(self.stdscr, list_y + i, x, row_str, attr)

    # -----------------------------------------------------------------------
    # Key handling
    # -----------------------------------------------------------------------

    def _handle_key(self, key) -> bool:
        rules = self._rules_for_chain(self.current_chain)
        all_chains = self._all_chains()

        if key == ord('q'):
            if confirm_dialog(self.stdscr, "Quit", "Quit nftpost?"):
                return False

        elif key == curses.KEY_UP:
            if self.focus_right:
                self.selected_rule_idx = max(0, self.selected_rule_idx - 1)
            else:
                prev = self.selected_chain_idx
                self.selected_chain_idx = max(0, self.selected_chain_idx - 1)
                if self.selected_chain_idx != prev:
                    self.selected_rule_idx = 0

        elif key == curses.KEY_DOWN:
            if self.focus_right:
                self.selected_rule_idx = min(
                    len(rules) - 1 if rules else 0,
                    self.selected_rule_idx + 1)
            else:
                prev = self.selected_chain_idx
                self.selected_chain_idx = min(len(all_chains) - 1,
                                              self.selected_chain_idx + 1)
                if self.selected_chain_idx != prev:
                    self.selected_rule_idx = 0

        elif key in (9, curses.KEY_RIGHT, curses.KEY_LEFT):  # Tab/arrows toggle panel focus
            rules = self._rules_for_chain(self.current_chain)
            if not self.focus_right:
                self.focus_right = True
                self.selected_rule_idx = min(self.selected_rule_idx,
                                             max(0, len(rules) - 1))
            else:
                self.focus_right = False

        elif key in (10, 13):  # Enter
            rules = self._rules_for_chain(self.current_chain)
            if self.focus_right and rules:
                self._do_edit()   # Enter on highlighted rule = edit
            elif not self.focus_right:
                self.focus_right = True   # Enter from chain panel = move focus right
                self.selected_rule_idx = min(self.selected_rule_idx,
                                             max(0, len(rules) - 1))

        elif key == ord('s'):
            self._do_save()

        elif key == ord('l'):
            self._do_load()

        elif key == ord('i'):
            self.focus_right = False
            self._do_insert()

        elif key == ord('a'):
            self.focus_right = False
            self._do_add()

        elif key == ord('e'):
            self._do_edit()

        elif key == ord('d'):
            self._do_delete()

        elif key == ord('o'):
            self._do_order()

        elif key == ord('p'):
            self._do_policy()

        elif key == ord('n'):
            self._do_new_chain()

        elif key == ord('x'):
            self._do_delete_chain()

        elif key == ord('g'):
            self._do_generate()

        return True

    def _clear_status(self):
        self.status_msg = ""

    # -----------------------------------------------------------------------
    # Actions
    # -----------------------------------------------------------------------

    def _filter_fields_for(self, chain: str) -> list:
        """Return FILTER_FIELDS with action options populated for this chain's table."""
        actions = self._available_actions(chain)
        return [
            (fname, label, (actions if fname == "action" else opts), ftype)
            for fname, label, opts, ftype in FILTER_FIELDS
        ]

    def _require_config(self) -> bool:
        if self.config_id is not None:
            return True
        msg_dialog(self.stdscr, "No Config",
                   ["No config is loaded.",
                    "Use l:load to load or create one."])
        return False

    def _write_config(self, cid: int):
        """Write current in-memory state to the given config id."""
        all_filter_chains = (FILTER_CHAINS + MANGLE_CHAINS +
                             [uc.name for uc in self.user_chains if uc.table != "nat"])
        for chain in all_filter_chains:
            self.db.conn.execute(
                "DELETE FROM filter_rules WHERE config_id=? AND chain=?", (cid, chain))
            for pos, rule in enumerate(self.filter_rules.get(chain, [])):
                rule.position = pos
                self.db.insert_filter_rule(cid, rule)
        for chain in NAT_CHAINS:
            self.db.conn.execute(
                "DELETE FROM nat_rules WHERE config_id=? AND chain=?", (cid, chain))
            for pos, rule in enumerate(self.nat_rules.get(chain, [])):
                rule.position = pos
                self.db.insert_nat_rule(cid, rule)
        self.db.conn.execute("DELETE FROM user_chains WHERE config_id=?", (cid,))
        for uc in self.user_chains:
            self.db.conn.execute(
                "INSERT OR IGNORE INTO user_chains (config_id,name,table_name) VALUES (?,?,?)",
                (cid, uc.name, uc.table))
        for chain, policy in self.policies.items():
            self.db.save_policy(cid, chain, policy)
        self.db.conn.commit()

    def _do_save(self):
        configs = self.db.list_configs()
        NEW = "[ Save as new name... ]"
        # build pick list: existing configs + new-name option
        choices = ([self.config_name] if self.config_name and self.config_name in configs else []) + \
                  [c for c in configs if c != self.config_name] + \
                  [NEW]
        chosen = pick_dialog(self.stdscr, "Save Config",
                             choices, self.config_name or NEW)
        if chosen is None:
            return
        if chosen == NEW:
            from datetime import datetime
            default_name = datetime.now().strftime("%Y-%m-%d_%H:%M:%S")
            name = input_dialog(self.stdscr, "Save As", "New config name: ",
                                default_name)
            if not name or not name.strip():
                return
            name = name.strip()
        else:
            name = chosen

        # create config record if it doesn't exist yet
        cid = self.db.config_id(name)
        if cid is None:
            cid = self.db.create_config(name)

        self._write_config(cid)
        self.config_id   = cid
        self.config_name = name
        self.info(f"Saved config '{name}'.")

    def _do_load(self):
        configs = self.db.list_configs()
        NEW = "[ New blank config... ]"
        choices = [NEW] + configs
        chosen = pick_dialog(self.stdscr, "Load Config",
                             choices, self.config_name or "")
        if chosen is None:
            return

        if chosen == NEW:
            name = input_dialog(self.stdscr, "New Config", "Config name: ")
            if not name or not name.strip():
                return
            name = name.strip()
            if self.db.config_id(name) is not None:
                msg_dialog(self.stdscr, "Error",
                           [f"Config '{name}' already exists.",
                            "Select it from the list to load it."])
                return
            cid = self.db.create_config(name)
            self.config_id   = cid
            self.config_name = name
            self.policies    = self.db.load_policies(cid)
            self.user_chains = []
            self.filter_rules = {ch: [] for ch in FILTER_CHAINS + MANGLE_CHAINS}
            self.nat_rules    = {ch: [] for ch in NAT_CHAINS}
            self.selected_chain_idx = 0
            self.selected_rule_idx  = 0
            self.focus_right = False
            self.info(f"New config '{name}' created.")
            return

        cid = self.db.config_id(chosen)
        if cid is None:
            return
        self.config_id   = cid
        self.config_name = chosen
        self.policies    = self.db.load_policies(cid)
        self.user_chains = self.db.load_user_chains(cid)
        self.filter_rules = {}
        for ch in FILTER_CHAINS + MANGLE_CHAINS:
            self.filter_rules[ch] = self.db.load_filter_rules(cid, ch)
        for uc in self.user_chains:
            if uc.table != "nat":
                self.filter_rules[uc.name] = self.db.load_filter_rules(cid, uc.name)
        self.nat_rules = {}
        for ch in NAT_CHAINS:
            self.nat_rules[ch] = self.db.load_nat_rules(cid, ch)
        self.selected_rule_idx  = 0
        self.selected_chain_idx = min(self.selected_chain_idx,
                                      len(self._all_chains()) - 1)
        self.info(f"Loaded config '{chosen}'.")

    def _do_new_chain(self):
        if not self._require_config():
            return
        name = input_dialog(self.stdscr, "New User Chain", "Chain name: ")
        if not name:
            return
        name = name.strip().upper()
        if not name or not name.replace("_","").replace("-","").isalnum():
            msg_dialog(self.stdscr, "Error", ["Invalid chain name.",
                                              "Use letters, digits, _ or - only."])
            return
        # check for collision with builtins or existing user chains
        if name in BUILTIN_CHAINS or any(uc.name == name for uc in self.user_chains):
            msg_dialog(self.stdscr, "Error", [f"Chain '{name}' already exists."])
            return
        table = pick_dialog(self.stdscr, "Table for chain", USER_CHAIN_TABLES, "filter")
        if table is None:
            return
        uc = UserChain(name=name, table=table)
        self.user_chains.append(uc)
        self.filter_rules[name] = []
        # jump to the new chain in the left panel
        self.selected_chain_idx = self._all_chains().index(name)
        self.selected_rule_idx = 0
        self.focus_right = False
        self.info(f"User chain '{name}' created in {table} table (unsaved).")

    def _do_delete_chain(self):
        chain = self.current_chain
        if not self._is_user_chain(chain):
            msg_dialog(self.stdscr, "Delete Chain",
                       ["Only user-defined chains can be deleted.",
                        f"'{chain}' is a built-in chain."])
            return
        rules = self._rules_for_chain(chain)
        lines = [f"Delete user chain '{chain}'?"]
        if rules:
            lines.append(f"  ({len(rules)} rule(s) will also be deleted)")
        # check for jump references in other chains
        refs = []
        for ch, rulelist in self.filter_rules.items():
            if ch == chain:
                continue
            for r in rulelist:
                if r.action == f"-> {chain}":
                    refs.append(ch)
                    break
        if refs:
            lines.append(f"  WARNING: still referenced from: {', '.join(refs)}")
        if not confirm_dialog(self.stdscr, "Delete Chain", lines[0]):
            return
        # remove from in-memory structures
        self.user_chains = [uc for uc in self.user_chains if uc.name != chain]
        self.filter_rules.pop(chain, None)
        # delete from DB if config saved
        if self.config_id:
            self.db.delete_user_chain(self.config_id, chain)
        # move selection to last builtin chain
        self.selected_chain_idx = min(self.selected_chain_idx,
                                      len(self._all_chains()) - 1)
        self.selected_rule_idx = 0
        self.error(f"Chain '{chain}' deleted.")

    def _do_generate(self):
        if not self.config_name:
            msg_dialog(self.stdscr, "Generate",
                       ["No config loaded.", "Use l:load to load or create one."])
            return

        FMT_NFT = "nft script  (nft -f <file>)"
        FMT_IPT = "iptables-save  (iptables-restore < <file>)"
        FMT_BOTH = "both formats"
        fmt = pick_dialog(self.stdscr, "Generate -- choose format",
                          [FMT_NFT, FMT_IPT, FMT_BOTH])
        if fmt is None:
            return

        written = []

        if fmt in (FMT_NFT, FMT_BOTH):
            script = generate_nft_script(
                self.config_name, self.policies,
                self.filter_rules, self.nat_rules, self.user_chains)
            fd, path = tempfile.mkstemp(prefix="nftpost_", suffix=".nft")
            with os.fdopen(fd, "w") as f:
                f.write(script)
            os.chmod(path, 0o750)
            written.append(("nft", path))

        if fmt in (FMT_IPT, FMT_BOTH):
            script = generate_ipt_save(
                self.config_name, self.policies,
                self.filter_rules, self.nat_rules, self.user_chains)
            fd, path = tempfile.mkstemp(prefix="nftpost_", suffix=".ipt")
            with os.fdopen(fd, "w") as f:
                f.write(script)
            os.chmod(path, 0o640)
            written.append(("ipt", path))

        msg_lines = []
        for kind, path in written:
            if kind == "nft":
                msg_lines += [f"nft script:", f"  {path}",
                              f"  apply: sudo nft -f {path}", ""]
            else:
                msg_lines += [f"iptables-save:", f"  {path}",
                              f"  apply: sudo iptables-restore < {path}", ""]

        msg_dialog(self.stdscr, "Generate -- done", msg_lines)
        paths = ", ".join(p for _, p in written)
        self.info(f"Generated: {paths}")

    def _do_add(self):
        if not self._require_config():
            return
        chain = self.current_chain
        if self._is_nat_chain(chain):
            rule = NatRule(chain=chain)
            saved = rule_form_dialog(self.stdscr, f"Add NAT Rule -- {chain}", rule, NAT_FIELDS)
            if saved:
                self.nat_rules.setdefault(chain, [])
                rule.position = len(self.nat_rules[chain])
                self.nat_rules[chain].append(rule)
                self.selected_rule_idx = len(self.nat_rules[chain]) - 1
                self.warn("Rule added (unsaved -- press s to save).")
        else:
            rule = FilterRule(chain=chain)
            fields = self._filter_fields_for(chain)
            saved = rule_form_dialog(self.stdscr, f"Add Rule -- {chain}", rule, fields)
            if saved:
                self.filter_rules.setdefault(chain, [])
                rule.position = len(self.filter_rules[chain])
                self.filter_rules[chain].append(rule)
                self.selected_rule_idx = len(self.filter_rules[chain]) - 1
                self.warn("Rule added (unsaved -- press s to save).")

    def _do_insert(self):
        if not self._require_config():
            return
        chain = self.current_chain
        rules = self._rules_for_chain(chain)

        if not rules:
            self._do_add()
            return

        if self._is_nat_chain(chain):
            rule = NatRule(chain=chain)
            saved = rule_form_dialog(self.stdscr, f"Insert NAT Rule -- {chain}", rule, NAT_FIELDS)
            if saved:
                insert_at = self.selected_rule_idx
                self.nat_rules[chain].insert(insert_at, rule)
                self.warn(f"Rule inserted at position {insert_at + 1} (unsaved).")
        else:
            rule = FilterRule(chain=chain)
            fields = self._filter_fields_for(chain)
            saved = rule_form_dialog(self.stdscr, f"Insert Rule -- {chain}", rule, fields)
            if saved:
                self.filter_rules.setdefault(chain, [])
                insert_at = self.selected_rule_idx
                self.filter_rules[chain].insert(insert_at, rule)
                self.warn(f"Rule inserted at position {insert_at + 1} (unsaved).")

    def _do_edit(self):
        chain = self.current_chain
        rules = self._rules_for_chain(chain)
        if not rules:
            msg_dialog(self.stdscr, "Edit Rule", ["No rules in this chain."])
            return
        idx = self.selected_rule_idx
        if idx >= len(rules):
            idx = max(0, len(rules) - 1)
            self.selected_rule_idx = idx
        rule = rules[idx]
        if self._is_nat_chain(chain):
            saved = rule_form_dialog(
                self.stdscr, f"Edit NAT Rule {idx+1} -- {chain}", rule, NAT_FIELDS)
        else:
            fields = self._filter_fields_for(chain)
            saved = rule_form_dialog(
                self.stdscr, f"Edit Rule {idx+1} -- {chain}", rule, fields)
        if saved:
            self.focus_right = True
            self.warn(f"Rule {idx+1} updated (unsaved -- press s to save).")

    def _do_delete(self):
        chain = self.current_chain
        rules = self._rules_for_chain(chain)
        if not rules:
            return
        idx = self.selected_rule_idx
        if idx >= len(rules):
            return
        rule = rules[idx]
        summary = (rule_summary_nat(rule) if self._is_nat_chain(chain)
                   else rule_summary_filter(rule))
        if not confirm_dialog(self.stdscr, "Delete Rule", f"Delete rule {idx+1}?"):
            return
        if self._is_nat_chain(chain):
            if rule.id:
                self.db.delete_nat_rule(rule.id)
            self.nat_rules[chain].pop(idx)
        else:
            if rule.id:
                self.db.delete_filter_rule(rule.id)
            self.filter_rules[chain].pop(idx)
        new_len = len(self._rules_for_chain(chain))
        self.selected_rule_idx = min(idx, max(0, new_len - 1))
        self.error("Rule deleted.")

    def _do_order(self):
        chain = self.current_chain
        rules = self._rules_for_chain(chain)
        if len(rules) < 2:
            msg_dialog(self.stdscr, "Order Rule", ["Need at least 2 rules to reorder."])
            return

        # prompt for rule number to move
        raw = input_dialog(self.stdscr, "Order Rule",
                           f"Move rule # (1-{len(rules)}): ",
                           str(self.selected_rule_idx + 1))
        if raw is None:
            return
        try:
            move_idx = int(raw.strip()) - 1
            if not (0 <= move_idx < len(rules)):
                raise ValueError
        except ValueError:
            msg_dialog(self.stdscr, "Error", [f"Invalid rule number: {raw}"])
            return

        # prompt for target rule number
        raw2 = input_dialog(self.stdscr, "Order Rule",
                            f"Insert before/after rule # (1-{len(rules)}): ",
                            str(move_idx + 1))
        if raw2 is None:
            return
        try:
            target_idx = int(raw2.strip()) - 1
            if not (0 <= target_idx < len(rules)):
                raise ValueError
        except ValueError:
            msg_dialog(self.stdscr, "Error", [f"Invalid target: {raw2}"])
            return

        # prompt before or after
        ba = input_dialog(self.stdscr, "Order Rule",
                          "Insert [b:before / a:after]: ")
        if ba is None:
            return
        ba = ba.strip().lower()
        if ba not in ("b", "a", "before", "after"):
            return

        # perform reorder
        rule = rules.pop(move_idx)
        # adjust target for removal
        if move_idx < target_idx:
            target_idx -= 1
        insert_pos = target_idx if ba.startswith("b") else target_idx + 1
        rules.insert(insert_pos, rule)

        # write back
        if self._is_nat_chain(chain):
            self.nat_rules[chain] = rules
        else:
            self.filter_rules[chain] = rules

        self.selected_rule_idx = insert_pos
        self.warn(f"Rule moved to position {insert_pos + 1} (unsaved).")

    def _do_policy(self):
        chain = self.current_chain
        if chain not in POLICY_CHAINS:
            msg_dialog(self.stdscr, "Policy",
                       [f"Chain '{chain}' does not support a default policy."])
            return
        current = self.policies.get(chain, "ACCEPT")
        chosen = pick_dialog(self.stdscr, f"Policy for {chain}", VALID_POLICIES, current)
        if chosen:
            self.policies[chain] = chosen
            if self.config_id:
                self.db.save_policy(self.config_id, chain, chosen)
            self.info(f"{chain} policy set to {chosen}.")

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main(stdscr, use_256: bool = True):
    app = NftpostApp(stdscr, use_256=use_256)
    app.run()

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(
        prog="nftpost",
        description="nftpost -- iptables-paradigm nftables rule generator",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=textwrap.dedent("""\
            keybinds (main screen):
              q          quit
              s          save config (pick existing name or save as new)
              l          load config (or create a new blank config)
              a          add rule to current chain
              i          insert rule before selected rule
              e / Enter  edit selected rule
              d          delete selected rule
              o          reorder rule (move before/after another)
              p          set default policy for current chain
              n          create new user-defined chain
              x          delete user-defined chain
              g          generate nft script to /tmp/

            navigation:
              Up/Down    move between chains (left panel) or rules (right panel)
              Tab        toggle focus between chain list and rule list
              Left/Right toggle focus between chain list and rule list

            database:
              config is stored in ~/.nftpost.db
              multiple named configs can be saved and loaded
        """),
    )
    parser.add_argument(
        "-8", "--8color",
        dest="use_8color",
        action="store_true",
        default=False,
        help="use 8-color mode instead of 256-color (for limited terminals)",
    )
    args = parser.parse_args()
    use_256 = not args.use_8color

    os.environ.setdefault("ESCDELAY", "25")
    try:
        curses.wrapper(main, use_256)
    except KeyboardInterrupt:
        pass
