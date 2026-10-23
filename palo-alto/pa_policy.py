#!/usr/bin/env python3
"""Palo Alto allow-list for the CCDC topology, built from ccdc.conf.

Only the scored services (PA_INBOUND) get in from outside, only PA_OUTBOUND gets out,
and everything else between the outside and inside zones is dropped and logged.

Usage: pa_policy.py COMMAND [options]
  plan            show what the firewall has (zones, NAT, rules) and the rules this would add
  cli             print the same change as PAN-OS CLI "set" commands (fallback if the API fails)
  apply           make the change: backup + snapshot, add the rules at the top, commit, and
                  roll back automatically unless you type "yes" within --timeout seconds
  verify          what the drop rules dropped recently - scorer traffic here = add the port
  block IP        drop all traffic from/to IP (an attacker - never the scoring engine)
  unblock IP      remove a block

Options:
  --host IP       firewall management IP (default PA_MGMT from ccdc.conf)
  --user NAME     admin user (default admin)
  --config FILE   default ../ccdc.conf
  --offline FILE  plan/cli from a saved config XML instead of the live firewall
  --timeout SEC   apply: seconds to test and confirm before rollback (default 300)
  --force         apply even if the firewall has uncommitted changes (they get committed too)

How the rules work:
  - Each server rule matches the private AND public address: PAN-OS security rules use the
    pre-NAT destination address with the post-NAT zone, and NAT may be on the Palo Alto or
    the VyOS router. Source is always any (rule: public services open to every source IP).
  - The rules go to the TOP of the rule base. Old rules are not deleted; the CCDC drop rules
    above them shadow the old allow-any rules for outside<->inside traffic only.
  - Traffic between LAN hosts never passes the firewall (same subnet): host firewalls
    (deploy.sh / deploy.ps1) cover that.
  - The outside interface (and the inside one, if you manage the firewall through the
    management IP) gets a ping-only management profile: ICMP stays up (rule), no web/SSH.
  - The management port keeps HTTPS only (web UI and this tool); SSH, Telnet and HTTP are
    switched off - use the VM console for the CLI.
  - SSH_SCORED=no in ccdc.conf drops port 22 from every PA_INBOUND entry.
"""
import argparse
import getpass
import ipaddress
import os
import queue
import re
import shlex
import signal
import ssl
import sys
import threading
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape, quoteattr

HERE = os.path.dirname(os.path.abspath(__file__))
PREFIX = 'CCDC-'
BLOCK_PREFIX = 'CCDC-blk-'
BLOCK_TAG = 'ccdc-block'
BLOCK_GROUP = 'CCDC-blocked'
MGMT_PROFILE = 'CCDC-ping-only'
# Management port services: HTTPS (web UI, API) stays; console for the CLI
MGMT_SERVICES = '<disable-ssh>yes</disable-ssh><disable-telnet>yes</disable-telnet><disable-http>yes</disable-http>'


def die(msg):
    print(f'ERROR: {msg}', file=sys.stderr)
    sys.exit(1)


# ------------------------------------------------------------------ ccdc.conf
def read_conf(path):
    """NAME=value and NAME=( ... ) lines of the bash config (arrays may span lines)."""
    conf, lines, i = {}, open(path).read().splitlines(), 0
    while i < len(lines):
        m = re.match(r'^([A-Za-z_][A-Za-z0-9_]*)=(.*)$', lines[i])
        i += 1
        if not m:
            continue
        name, value = m.groups()
        if not value.startswith('('):
            words = shlex.split(value, comments=True)
            conf[name] = words[0] if words else ''
            continue
        words, text = [], value[1:]
        while True:
            lex = shlex.shlex(text, posix=True, punctuation_chars='()')
            lex.whitespace_split = True
            toks = list(lex)
            if ')' in toks:
                words += toks[:toks.index(')')]
                break
            words += toks
            if i >= len(lines):
                break
            text = lines[i]
            i += 1
        conf[name] = words
    return conf


def parse_ports(spec, where):
    """'tcp/22,80 udp/53' -> {'tcp': '22,80', 'udp': '53'}"""
    out = {}
    for part in spec.split():
        proto, _, ports = part.partition('/')
        if proto not in ('tcp', 'udp') or not ports or not all(p.replace('-', '').isdigit() for p in ports.split(',')):
            die(f'{where}: bad port spec "{part}" (expected tcp/22,80 or udp/53)')
        out[proto] = ports
    return out


# ------------------------------------------------------------------ the plan
class Plan:
    def __init__(self, conf):
        self.conf = conf
        ext = conf.get('EXTERNAL', '')
        try:
            self.public_net = ipaddress.ip_network(ext)
        except ValueError:
            die('ccdc.conf: set EXTERNAL to the team\'s public range (172.25.<20+team>.0/24)')
        self.inside = ipaddress.ip_network(conf.get('INSIDE') or die('ccdc.conf: INSIDE is empty'))
        self.addresses = {}    # name -> cidr
        self.groups = {}       # name -> [members]
        self.services = {}     # name -> (proto, ports)
        self.rules = []        # dicts, in order
        self.hosts = {}        # var -> (private, public)

    def ip(self, var):
        v = self.conf.get(var, '')
        if not v:
            return None
        try:
            ipaddress.ip_address(v)
        except ValueError:
            die(f'ccdc.conf: {var}="{v}" is not an IP address')
        return v

    def host_group(self, var):
        if var in self.hosts:
            return f'{PREFIX}{var}'
        priv = self.ip(var) or die(f'ccdc.conf: {var} is used in PA_INBOUND/PA_OUTBOUND but empty')
        if ipaddress.ip_address(priv) not in self.inside:
            die(f'ccdc.conf: {var}={priv} is not inside INSIDE={self.inside}')
        pub = str(list(self.public_net.hosts())[0]).rsplit('.', 1)[0] + '.' + priv.rsplit('.', 1)[1]
        self.hosts[var] = (priv, pub)
        self.addresses[f'{PREFIX}{var}-int'] = f'{priv}/32'
        self.addresses[f'{PREFIX}{var}-pub'] = f'{pub}/32'
        self.groups[f'{PREFIX}{var}'] = [f'{PREFIX}{var}-int', f'{PREFIX}{var}-pub']
        return f'{PREFIX}{var}'

    def service_names(self, label, ports):
        names = []
        for proto, p in ports.items():
            n = f'{PREFIX}{label}-{proto}'
            self.services[n] = (proto, p)
            names.append(n)
        return names

    def rule(self, name, frm, to, src, dst, svc, action='allow', app=('any',), desc=''):
        self.rules.append(dict(name=PREFIX + name, frm=frm, to=to, src=list(src), dst=list(dst),
                               svc=list(svc), app=list(app), action=action, desc=desc))

    def build(self, outside, inside):
        c = self.conf
        self.addresses[f'{PREFIX}INSIDE-net'] = str(self.inside)
        # Blocked attackers: a dynamic group, filled by tagging address objects (block command)
        self.rule('block-in', [outside], ['any'], [BLOCK_GROUP], ['any'], ['any'], 'drop',
                  desc='attacker IPs (pa_policy.py block)')
        self.rule('block-out', [inside], [outside], ['any'], [BLOCK_GROUP], ['any'], 'drop',
                  desc='attacker IPs (pa_policy.py block)')
        if not c.get('PA_INBOUND'):
            die('ccdc.conf: PA_INBOUND is empty')
        ssh_scored = c.get('SSH_SCORED', 'yes') == 'yes'
        for entry in c['PA_INBOUND']:
            var, _, spec = entry.partition(':')
            grp = self.host_group(var)
            ports = parse_ports(spec, f'PA_INBOUND {var}')
            if not ssh_scored and 'tcp' in ports:   # one switch for scored SSH (ccdc.conf)
                ports['tcp'] = ','.join(p for p in ports['tcp'].split(',') if p != '22')
                if not ports['tcp']:
                    del ports['tcp']
            if not ports:
                continue
            self.rule(f'in-{var}', [outside], [inside], ['any'], [grp], self.service_names(var, ports),
                      desc=f'scored services on {var}')
        self.groups[f'{PREFIX}servers'] = [f'{PREFIX}{v}' for v in self.hosts]
        self.rule('in-ping', [outside], [inside], ['any'], [f'{PREFIX}servers'], ['any'],
                  app=['ping', 'icmp'], desc='rule: keep ICMP up; ping is scored')
        kali_net, splunk, ad = c.get('KALI_NET'), self.ip('SPLUNK'), self.ip('AD')
        if kali_net:
            # Kali sits behind the VyOS router, so it reaches the LAN from the outside zone
            self.addresses[f'{PREFIX}KALI-net'] = str(ipaddress.ip_network(kali_net))
            if splunk:
                self.addresses[f'{PREFIX}SPLUNK-int'] = f'{splunk}/32'
                self.rule('in-kali-splunk', [outside], [inside], [f'{PREFIX}KALI-net'], [f'{PREFIX}SPLUNK-int'],
                          self.service_names('fwd', {'tcp': '9997'}), desc='Kali forwarder logs')
            if ad:
                self.addresses[f'{PREFIX}AD-int'] = f'{ad}/32'
                self.rule('in-kali-ntp', [outside], [inside], [f'{PREFIX}KALI-net'], [f'{PREFIX}AD-int'],
                          self.service_names('ntp', {'udp': '123'}), desc='Kali time sync')
        for n, entry in enumerate(c.get('PA_OUTBOUND', []), 1):
            var, _, spec = entry.partition(':')
            src = f'{PREFIX}INSIDE-net' if var == 'INSIDE' else self.host_group(var)
            self.rule(f'out-{var}' if var != 'INSIDE' else 'out-lan', [inside], [outside], [src], ['any'],
                      self.service_names(f'out{n}', parse_ports(spec, f'PA_OUTBOUND {var}')),
                      desc=f'outbound from {var}')
        self.rule('out-ping', [inside], [outside], [f'{PREFIX}INSIDE-net'], ['any'], ['any'],
                  app=['ping', 'icmp', 'traceroute'], desc='ping out')
        self.rule('deny-in', [outside], [inside], ['any'], ['any'], ['any'], 'drop',
                  desc='everything else in - check with pa_policy.py verify')
        self.rule('deny-out', [inside], [outside], ['any'], ['any'], ['any'], 'drop',
                  desc='everything else out (reverse shells, C2)')
        names = [r['name'] for r in self.rules]
        assert len(names) == len(set(names)), names


# ------------------------------------------------------------------ firewall access
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE   # firewalls use self-signed certificates


class PAError(Exception):
    pass


class Firewall:
    def __init__(self, host, user):
        self.host = host
        pw = getpass.getpass(f'Password for {user}@{host}: ')
        root = self._post({'type': 'keygen', 'user': user, 'password': pw})
        self.key = root.findtext('.//key') or die('no API key returned')

    def _post(self, params, raw=False, timeout=180):
        data = urllib.parse.urlencode(params).encode()
        req = urllib.request.Request(f'https://{self.host}/api/', data=data)
        try:
            with urllib.request.urlopen(req, context=CTX, timeout=timeout) as r:
                body = r.read()
        except Exception as e:
            raise PAError(f'cannot reach https://{self.host}/api/: {e}')
        if raw:
            return body
        root = ET.fromstring(body)
        if root.get('status') != 'success':
            msg = ' '.join(t.strip() for t in root.itertext() if t.strip())
            raise PAError(msg or ET.tostring(root, encoding='unicode'))
        return root

    def api(self, **params):
        return self._post({**params, 'key': self.key})

    def op(self, cmd):
        return self.api(type='op', cmd=cmd)

    def running(self):
        return self.api(type='config', action='show', xpath='/config').find('result/config')

    def candidate(self, xpath):
        return self.api(type='config', action='get', xpath=xpath).find('result')

    def export(self):
        return self._post({'type': 'export', 'category': 'configuration', 'key': self.key}, raw=True)

    def wait_job(self, job, what):
        print(f'{what}: job {job} ', end='', flush=True)
        for _ in range(600):
            j = self.op(f'<show><jobs><id>{job}</id></jobs></show>').find('result/job')
            if j is not None and j.findtext('status') == 'FIN':
                print()
                ok = j.findtext('result') == 'OK'
                details = ' '.join(t.strip() for t in j.find('details').itertext() if t.strip()) if j.find('details') is not None else ''
                if details:
                    print(f'  {details}')
                return ok
            print('.', end='', flush=True)
            time.sleep(3)
        print()
        return False

    def commit(self, what='commit'):
        r = self.api(type='commit', cmd='<commit></commit>')
        job = r.findtext('result/job')
        if not job:
            print(f'{what}: {r.findtext("result/msg") or "nothing to commit"}')
            return True
        return self.wait_job(job, what)


# ------------------------------------------------------------------ discovery
def members(el, tag):
    return [m.text for m in el.findall(f'{tag}/member')] if el is not None else []


class Topology:
    def __init__(self, config):
        self.config = config
        dev = config.find('devices/entry')
        if dev is None:
            die('no devices/entry in the config')
        self.dev_name = dev.get('name')
        vsys = dev.find('vsys/entry')
        self.vsys_name = vsys.get('name')
        self.vsys = vsys
        self.dev_xpath = f"/config/devices/entry[@name='{self.dev_name}']"
        self.vsys_xpath = f"{self.dev_xpath}/vsys/entry[@name='{self.vsys_name}']"
        self.objects = {}
        for scope in (config.find('shared'), vsys):
            for a in (scope.findall('address/entry') if scope is not None else []):
                self.objects[a.get('name')] = a.findtext('ip-netmask') or a.findtext('ip-range') or a.findtext('fqdn') or '?'
        # interface -> (xpath, [ip/mask], mgmt profile)
        self.interfaces = {}
        for e in dev.findall('network/interface/ethernet/entry'):
            l3 = e.find('layer3')
            if l3 is None:
                continue
            base = f"{self.dev_xpath}/network/interface/ethernet/entry[@name='{e.get('name')}']/layer3"
            self._add_if(e.get('name'), base, l3)
            for u in l3.findall('units/entry'):
                self._add_if(u.get('name'), f"{base}/units/entry[@name='{u.get('name')}']", u)
        self.zone_of = {}
        for z in vsys.findall('zone/entry'):
            for m in members(z.find('network'), 'layer3'):
                self.zone_of[m] = z.get('name')
        mgmt = dev.find('deviceconfig/system')
        self.mgmt_ip = mgmt.findtext('ip-address') if mgmt is not None else None
        self.permitted = [e.get('name') for e in mgmt.findall('permitted-ip/entry')] if mgmt is not None else []
        rb = vsys.find('rulebase')
        self.security = rb.findall('security/rules/entry') if rb is not None else []
        self.nat = rb.findall('nat/rules/entry') if rb is not None else []

    def _add_if(self, name, xpath, el):
        ips = []
        for e in el.findall('ip/entry'):
            v = e.get('name')
            ips.append(self.objects.get(v, v))
        self.interfaces[name] = (xpath, ips, el.findtext('interface-management-profile') or '')

    def interface_with(self, ip):
        want = ipaddress.ip_address(ip)
        for name, (_, ips, _) in self.interfaces.items():
            for cidr in ips:
                try:
                    if ipaddress.ip_interface(cidr).ip == want:
                        return name
                except ValueError:
                    pass
        return None

    def resolve(self, name):
        return self.objects.get(name, name)


def discover(topo, conf):
    inside_net = ipaddress.ip_network(conf['INSIDE'])
    in_if = next((n for n, (_, ips, _) in topo.interfaces.items() for c in ips
                  if _in(c, inside_net)), None)
    out_if = topo.interface_with(conf['PA_OUTSIDE']) if conf.get('PA_OUTSIDE') else None
    print('Interfaces:')
    for n, (_, ips, prof) in sorted(topo.interfaces.items()):
        tag = ' <- inside' if n == in_if else ' <- outside' if n == out_if else ''
        print(f'  {n:16} {", ".join(ips) or "-":24} zone {topo.zone_of.get(n, "-"):12} mgmt-profile {prof or "-"}{tag}')
    if not in_if:
        die(f'no interface with an address in INSIDE={inside_net} - check ccdc.conf against the firewall')
    if not out_if:
        die(f'no interface with PA_OUTSIDE={conf.get("PA_OUTSIDE")} - check ccdc.conf against the firewall')
    zin, zout = topo.zone_of.get(in_if), topo.zone_of.get(out_if)
    if not zin or not zout:
        die(f'{in_if if not zin else out_if} is not in a zone')
    if zin == zout:
        die(f'inside and outside interfaces are both in zone {zin} - this script needs two zones')
    others = sorted({z for i, z in topo.zone_of.items() if z not in (zin, zout) and topo.interfaces.get(i, (0, []))[1]})
    if others:
        print(f'  NOTE: other zones with addresses: {", ".join(others)} - not touched by these rules')
    print(f'Management IP {topo.mgmt_ip or "?"}; permitted IPs: {", ".join(topo.permitted) or "any (not restricted)"}')
    return in_if, out_if, zin, zout


def _in(cidr, net):
    try:
        return ipaddress.ip_interface(cidr).ip in net
    except ValueError:
        return False


def show_nat(topo, plan):
    print('\nNAT rules on the firewall:')
    if not topo.nat:
        print('  none - NAT is probably done on the VyOS router (fine: the rules match both addresses)')
    found = set()
    for r in topo.nat:
        st, dt = r.find('source-translation'), r.find('destination-translation')
        txt = lambda el: ' '.join(t.strip() for t in el.itertext() if t.strip()) if el is not None else ''
        src = [topo.resolve(s) for s in members(r, 'source')]
        dst = [topo.resolve(s) for s in members(r, 'destination')]
        flat = ' '.join(src + dst + [topo.resolve(w) for w in (txt(st) + ' ' + txt(dt)).split()])
        for var, (priv, pub) in plan.hosts.items():
            if priv in flat or pub in flat:
                found.add(var)
        dis = ' (disabled)' if r.findtext('disabled') == 'yes' else ''
        print(f'  {r.get("name")}{dis}: {",".join(members(r, "from"))} -> {",".join(members(r, "to"))}  '
              f'src {",".join(src)} dst {",".join(dst)}  snat [{txt(st)}] dnat [{txt(dt)}]')
    for var, (priv, pub) in plan.hosts.items():
        if var not in found and topo.nat:
            print(f'  NOTE: no NAT rule here mentions {var} ({priv} / {pub}) - check the VyOS router does it')


def show_existing(topo):
    print('\nCurrent security rules (top to bottom) - CCDC rules go above all of them:')
    for r in topo.security:
        dis = ' (disabled)' if r.findtext('disabled') == 'yes' else ''
        print(f'  {r.get("name")}{dis}: {",".join(members(r, "from"))} -> {",".join(members(r, "to"))} '
              f'app {",".join(members(r, "application"))} svc {",".join(members(r, "service"))} -> {r.findtext("action")}')


def show_plan(plan):
    print('\nRules to add, in order (each server rule = its private + public address):')
    for var, (priv, pub) in plan.hosts.items():
        print(f'  {PREFIX}{var:10} {priv} / {pub}')
    print()
    for i, r in enumerate(plan.rules, 1):
        svc = ', '.join(f'{plan.services[s][0]}/{plan.services[s][1]}' if s in plan.services else s for s in r['svc'])
        app = '' if r['app'] == ['any'] else f' app {",".join(r["app"])}'
        print(f'  {i:2}. {r["name"]:22} {r["frm"][0]} -> {r["to"][0]:10} src {",".join(r["src"]):18} '
              f'dst {",".join(r["dst"]):18} {svc}{app} -> {r["action"].upper()}')


# ------------------------------------------------------------------ rendering
def mem(tag, vals):
    return f'<{tag}>' + ''.join(f'<member>{escape(v)}</member>' for v in vals) + f'</{tag}>'


def rule_xml(r):
    return (f'<entry name={quoteattr(r["name"])}>' + mem('from', r['frm']) + mem('to', r['to'])
            + mem('source', r['src']) + mem('destination', r['dst']) + mem('source-user', ['any'])
            + mem('category', ['any']) + mem('application', r['app']) + mem('service', r['svc'])
            + f'<action>{r["action"]}</action><log-end>yes</log-end>'
            + f'<description>{escape(r["desc"])}</description></entry>')


def object_sets(plan, topo):
    """(parent xpath, element) for every object, in dependency order."""
    v = topo.vsys_xpath
    out = [(f'{v}/tag', f'<entry name="{BLOCK_TAG}"><color>color1</color></entry>')]
    out += [(f'{v}/address', f'<entry name={quoteattr(n)}><ip-netmask>{c}</ip-netmask></entry>') for n, c in plan.addresses.items()]
    out.append((f'{v}/address-group', f'<entry name="{BLOCK_GROUP}"><dynamic><filter>\'{BLOCK_TAG}\'</filter></dynamic></entry>'))
    # host groups before the group of groups
    for n, ms in sorted(plan.groups.items(), key=lambda kv: kv[0] == f'{PREFIX}servers'):
        out.append((f'{v}/address-group', f'<entry name={quoteattr(n)}>{mem("static", ms)}</entry>'))
    out += [(f'{v}/service', f'<entry name={quoteattr(n)}><protocol><{p}><port>{ports}</port></{p}></protocol></entry>')
            for n, (p, ports) in plan.services.items()]
    out += [(f'{v}/rulebase/security/rules', rule_xml(r)) for r in plan.rules]
    return out


def q(s):
    return f'"{s}"' if any(ch in s for ch in ' \'') else s


def lst(vals):
    return q(vals[0]) if len(vals) == 1 else '[ ' + ' '.join(q(x) for x in vals) + ' ]'


def cli_lines(plan, mgmt_ifs, permit):
    out = [f'set tag {BLOCK_TAG} color color1']
    out += [f'set address {n} ip-netmask {c}' for n, c in plan.addresses.items()]
    out.append(f'set address-group {BLOCK_GROUP} dynamic filter "\'{BLOCK_TAG}\'"')
    for n, ms in sorted(plan.groups.items(), key=lambda kv: kv[0] == f'{PREFIX}servers'):
        out.append(f'set address-group {n} static {lst(ms)}')
    out += [f'set service {n} protocol {p} port {ports}' for n, (p, ports) in plan.services.items()]
    for r in plan.rules:
        out.append(f'set rulebase security rules {r["name"]} from {lst(r["frm"])} to {lst(r["to"])} '
                   f'source {lst(r["src"])} destination {lst(r["dst"])} source-user any category any '
                   f'application {lst(r["app"])} service {lst(r["svc"])} action {r["action"]} log-end yes')
    out += [f'move rulebase security rules {r["name"]} top' for r in reversed(plan.rules)]
    out.append(f'set network profiles interface-management-profile {MGMT_PROFILE} ping yes')
    out += [f'set network interface ethernet {i} layer3 interface-management-profile {MGMT_PROFILE}'
            if '.' not in i else
            f'set network interface ethernet {i.split(".")[0]} layer3 units {i} interface-management-profile {MGMT_PROFILE}'
            for i in mgmt_ifs]
    if permit:
        out.append(f'# Management access only from the LAN (the NETLAB console still works). Skip this line if')
        out.append(f'# you manage the firewall from outside {permit}.')
        out.append(f'set deviceconfig system permitted-ip {permit}')
    out.append('set deviceconfig system service disable-ssh yes disable-telnet yes disable-http yes')
    return out


# ------------------------------------------------------------------ helpers
def ask(question, default=False):
    try:
        a = input(f'{question} {"[Y/n]" if default else "[y/N]"} ').strip()
    except EOFError:
        return default
    return a.lower().startswith('y') if a else default


def timed_input(prompt, timeout):
    """input() with a timeout that works on Linux and Windows. None on timeout / closed terminal."""
    qu = queue.Queue()

    def reader():
        try:
            qu.put(input(prompt))
        except Exception:
            qu.put(None)
    threading.Thread(target=reader, daemon=True).start()
    try:
        return qu.get(timeout=timeout)
    except queue.Empty:
        print()
        return None


def out_dir():
    d = '/root/ccdc/palo-alto' if hasattr(os, 'geteuid') and os.geteuid() == 0 else os.path.join(os.path.expanduser('~'), 'ccdc-palo-alto')
    os.makedirs(d, mode=0o700, exist_ok=True)
    return d


def my_source_ip(host):
    import socket
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect((host, 443))
            return s.getsockname()[0]
    except OSError:
        return None


def mgmt_changes(topo, conf, in_if, out_if, host):
    """Interfaces to set ping-only, and a permitted-ip entry to add (or None)."""
    ifs = [out_if]
    # Managing through the dedicated management IP? Then the inside interface needs no web/SSH.
    if host == topo.mgmt_ip and topo.interface_with(host) is None:
        ifs.append(in_if)
    permit = None
    me = my_source_ip(host)
    inside = ipaddress.ip_network(conf['INSIDE'])
    if host == topo.mgmt_ip and str(inside) not in topo.permitted:
        if me and ipaddress.ip_address(me) in inside:
            permit = str(inside)
        else:
            print(f'NOTE: this machine ({me}) is not in INSIDE - not restricting management access')
    return ifs, permit


# ------------------------------------------------------------------ commands
def load(args, conf):
    if args.offline:
        root = ET.parse(args.offline).getroot()
        cfg = root if root.tag == 'config' else root.find('.//config')
        return None, Topology(cfg)
    fw = Firewall(args.host, args.user)
    return fw, Topology(fw.running())


def cmd_plan(args, conf, cli=False):
    fw, topo = load(args, conf)
    in_if, out_if, zin, zout = discover(topo, conf)
    plan = Plan(conf)
    plan.build(zout, zin)
    if cli:
        ifs, permit = mgmt_changes(topo, conf, in_if, out_if, args.host) if fw else ([out_if], conf['INSIDE'])
        print('\n# Type in the firewall VM console: configure, then these lines, then: commit')
        print('# Only on a firewall without earlier CCDC- objects (apply cleans those up itself).')
        print('\n'.join(cli_lines(plan, ifs, permit)))
        return
    show_nat(topo, plan)
    show_existing(topo)
    show_plan(plan)


def clean_ccdc(fw, topo):
    """Delete earlier CCDC- rules and objects (not blocked IPs) so apply can be re-run."""
    v = topo.vsys_xpath
    for kind in ('rulebase/security/rules', 'address-group', 'address', 'service'):
        res = fw.candidate(f'{v}/{kind}')
        # Reverse creation order: groups that contain other groups (CCDC-servers) go first
        for e in reversed(list(res.iter('entry')) if res is not None else []):
            n = e.get('name') or ''
            if n.startswith(PREFIX) and not n.startswith(BLOCK_PREFIX) and n != BLOCK_GROUP:
                fw.api(type='config', action='delete', xpath=f"{v}/{kind}/entry[@name='{n}']")


def cmd_apply(args, conf):
    fw, topo = load(args, conf)
    in_if, out_if, zin, zout = discover(topo, conf)
    plan = Plan(conf)
    plan.build(zout, zin)
    show_nat(topo, plan)
    show_existing(topo)
    show_plan(plan)
    ifs, permit = mgmt_changes(topo, conf, in_if, out_if, args.host)
    print(f'\nManagement: ping-only profile on {", ".join(ifs)}; management port HTTPS only (no SSH/Telnet/HTTP)'
          + (f'; management access only from {permit}' if permit else ''))

    pending = (fw.op('<check><pending-changes></pending-changes></check>').findtext('result') or '').strip()
    if pending == 'yes' and not args.force:
        die('the firewall has uncommitted changes (someone else\'s?). Commit or revert them first, or use --force')
    if not ask(f'\nApply {len(plan.rules)} rules and commit?'):
        print('Nothing changed.')
        return

    stamp = time.strftime('%Y%m%d-%H%M%S')
    backup = os.path.join(out_dir(), f'running-{stamp}.xml')
    with open(backup, 'wb') as f:
        f.write(fw.export())
    os.chmod(backup, 0o600)
    snap = f'ccdc-before-policy-{stamp}.xml'
    fw.op(f'<save><config><to>{snap}</to></config></save>')
    print(f'Backup: {backup}   On the firewall: snapshot {snap}')

    try:
        clean_ccdc(fw, topo)
        for xpath, element in object_sets(plan, topo):
            fw.api(type='config', action='set', xpath=xpath, element=element)
        rules = f'{topo.vsys_xpath}/rulebase/security/rules'
        for r in reversed(plan.rules):
            fw.api(type='config', action='move', xpath=f"{rules}/entry[@name='{r['name']}']", where='top')
        fw.api(type='config', action='set', xpath=f'{topo.dev_xpath}/network/profiles/interface-management-profile',
               element=f'<entry name="{MGMT_PROFILE}"><ping>yes</ping></entry>')
        for i in ifs:
            fw.api(type='config', action='set', xpath=topo.interfaces[i][0],
                   element=f'<interface-management-profile>{MGMT_PROFILE}</interface-management-profile>')
        if permit:
            fw.api(type='config', action='set', xpath=f'{topo.dev_xpath}/deviceconfig/system/permitted-ip',
                   element=f'<entry name="{permit}"/>')
        fw.api(type='config', action='set', xpath=f'{topo.dev_xpath}/deviceconfig/system/service', element=MGMT_SERVICES)
    except PAError as e:
        print(f'Change failed: {e}\nRestoring the candidate config from {snap} (nothing was committed).')
        fw.op(f'<load><config><from>{snap}</from></config></load>')
        sys.exit(1)

    if hasattr(signal, 'SIGHUP'):
        signal.signal(signal.SIGHUP, signal.SIG_IGN)   # a dropped session still rolls back
    if not fw.commit():
        print(f'Commit FAILED - restoring {snap} into the candidate (running config unchanged).')
        fw.op(f'<load><config><from>{snap}</from></config></load>')
        sys.exit(1)

    print(f'\nCommitted. NOW: check Quotient - every service up? - and run "pa_policy.py verify" in another'
          f' terminal.\nNo "yes" within {args.timeout} s (or the session drops) = automatic rollback.')
    try:
        ans = timed_input(f'Type "yes" to keep the new policy: ', args.timeout)
    except KeyboardInterrupt:
        ans = None
    try:
        sys.stdout.write('\n')
        sys.stdout.flush()
    except OSError:                                  # terminal gone: roll back silently
        sys.stdout = sys.stderr = open(os.devnull, 'w')
    if (ans or '').strip() == 'yes':
        print(f'Kept. Roll back by hand: Device > Setup > Operations > Load named configuration snapshot > {snap}, Commit.')
        return 0
    print(f'Not confirmed - rolling back to {snap}...')
    fw.op(f'<load><config><from>{snap}</from></config></load>')
    if fw.commit('rollback commit'):
        print('Rolled back.')
        return 3
    else:
        print(f'ROLLBACK COMMIT FAILED - in the web UI: load snapshot {snap} and commit NOW')
        sys.stdout.flush()
        os._exit(1)


def cmd_verify(args, conf):
    fw, topo = load(args, conf)
    plan = Plan(conf)
    in_if, out_if, zin, zout = discover(topo, conf)
    plan.build(zout, zin)
    ours = {ip: var for var, (priv, pub) in plan.hosts.items() for ip in (priv, pub)}
    query = f"(rule eq '{PREFIX}deny-in') or (rule eq '{PREFIX}deny-out') or (rule eq '{PREFIX}block-in')"
    job = fw.api(type='log', **{'log-type': 'traffic'}, query=query, nlogs='1000').findtext('result/job')
    for _ in range(60):
        res = fw.api(type='log', action='get', **{'job-id': job}).find('result')
        if res.findtext('job/status') == 'FIN':
            break
        time.sleep(2)
    entries = res.findall('log/logs/entry')
    if not entries:
        print('\nNothing dropped by the CCDC rules in the recent traffic log.')
        return
    agg = {}
    for e in entries:
        k = (e.findtext('rule'), e.findtext('dst'), e.findtext('proto'), e.findtext('dport'))
        a = agg.setdefault(k, [0, set(), e.findtext('receive_time') or e.findtext('time_generated')])
        a[0] += 1
        a[1].add(e.findtext('src'))
    print(f'\nDropped by CCDC rules (newest {len(entries)} log entries):')
    for (rule, dst, proto, dport), (n, srcs, last) in sorted(agg.items(), key=lambda kv: -kv[1][0]):
        flag = ''
        if rule == f'{PREFIX}deny-in' and dst in ours:
            flag = f'   <- SCORER? {ours[dst]} {proto}/{dport}: if Quotient shows it down, add it to PA_INBOUND'
        print(f'  {n:5}x {rule:16} -> {dst}:{dport}/{proto}  from {", ".join(sorted(srcs)[:4])}'
              f'{" ..." if len(srcs) > 4 else ""}  last {last}{flag}')


def cmd_block(args, conf, unblock=False):
    ip = args.ip
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        die(f'{ip} is not an IP address')
    if not unblock:
        ours = [conf.get(k) for k in ('INSIDE', 'EXTERNAL', 'KALI_NET') if conf.get(k)] + ['172.16.0.0/24', '172.31.0.0/16']
        for net in ours:
            try:
                if addr in ipaddress.ip_network(net):
                    die(f'{ip} is in {net} - one of ours or the competition core. Not blocking.')
            except ValueError:
                pass
        print('Make sure this is NOT the scoring engine (Quotient checks would fail for every service).')
        if not ask(f'Block all traffic from/to {ip}?'):
            return
    fw = Firewall(args.host, args.user)
    topo = Topology(fw.running())
    name = BLOCK_PREFIX + ip.replace(':', '_')
    x = f"{topo.vsys_xpath}/address"
    if unblock:
        fw.api(type='config', action='delete', xpath=f"{x}/entry[@name='{name}']")
    else:
        fw.api(type='config', action='set', xpath=x,
               element=f'<entry name="{name}"><ip-netmask>{ip}</ip-netmask><tag><member>{BLOCK_TAG}</member></tag></entry>')
    if fw.commit():
        print(f'{"Unblocked" if unblock else "Blocked"} {ip}. (Needs the CCDC-block rules from apply.) '
              f'Note it for the incident report.')


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('command', choices=['plan', 'cli', 'apply', 'verify', 'block', 'unblock'])
    p.add_argument('ip', nargs='?')
    p.add_argument('--host')
    p.add_argument('--user', default='admin')
    p.add_argument('--config', default=os.path.join(HERE, '..', 'ccdc.conf'))
    p.add_argument('--offline')
    p.add_argument('--timeout', type=int, default=300)
    p.add_argument('--force', action='store_true')
    args = p.parse_args()
    conf = read_conf(args.config)
    args.host = args.host or conf.get('PA_MGMT') or die('no --host and PA_MGMT is empty')
    if args.offline and args.command not in ('plan', 'cli'):
        die('--offline only works with plan / cli')
    try:
        if args.command == 'plan':
            cmd_plan(args, conf)
        elif args.command == 'cli':
            cmd_plan(args, conf, cli=True)
        elif args.command == 'apply':
            rc = cmd_apply(args, conf) or 0
            # The confirmation prompt may leave a thread blocked on stdin; don't wait for it
            sys.stdout.flush()
            os._exit(rc)
        elif args.command == 'verify':
            cmd_verify(args, conf)
        elif args.command in ('block', 'unblock'):
            if not args.ip:
                die(f'usage: pa_policy.py {args.command} IP')
            cmd_block(args, conf, unblock=args.command == 'unblock')
    except PAError as e:
        die(str(e))
    except KeyboardInterrupt:
        print('\nInterrupted.')
        sys.exit(130)


if __name__ == '__main__':
    main()
