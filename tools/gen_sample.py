"""Generate a synthetic capture exercising every analyzer feature (pcap + pcapng)."""
import struct, random, base64, sys

random.seed(7)
T0 = 1762848000.0  # 2025-11-11 08:00 UTC
pkts = []  # (ts, bytes)

def mac(s): return bytes(int(x, 16) for x in s.split(':'))
def ip4(s): return bytes(int(x) for x in s.split('.'))

def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b)//2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def eth(src, dst, et, pl): return mac(dst) + mac(src) + struct.pack('!H', et) + pl

IPID = [1000]
def ipv4(src, dst, proto, pl, ttl=64, flags_frag=0x4000):
    IPID[0] += 1
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20+len(pl), IPID[0] & 0xffff, flags_frag, ttl, proto, 0, ip4(src), ip4(dst))
    h = h[:10] + struct.pack('!H', csum(h)) + h[12:]
    return h + pl

def tcp(src, dst, sp, dp, seq, ack, flags, pl=b'', win=64240, opts=b''):
    off = (20 + len(opts)) // 4
    h = struct.pack('!HHIIBBHHH', sp, dp, seq & 0xffffffff, ack & 0xffffffff, off << 4, flags, win, 0, 0) + opts
    ph = ip4(src) + ip4(dst) + struct.pack('!BBH', 0, 6, len(h)+len(pl))
    c = csum(ph + h + pl)
    h = h[:16] + struct.pack('!H', c) + h[18:]
    return h + pl

def udp(src, dst, sp, dp, pl):
    h = struct.pack('!HHHH', sp, dp, 8+len(pl), 0)
    return h + pl

F, S, R, P, A = 1, 2, 4, 8, 16

def add(t, frame): pkts.append((T0 + t, frame))

MAC = {
 'client': '3c:52:82:11:22:33', 'gw': '00:1a:2b:3c:4d:5e', 'attacker': 'de:ad:be:ef:00:01',
 'srv': '00:50:56:aa:bb:cc', 'victim': '3c:52:82:44:55:66', 'bcast': 'ff:ff:ff:ff:ff:ff',
}
CLIENT, GW, ATT, VICTIM, SRV = '192.168.10.25', '192.168.10.1', '192.168.10.66', '192.168.10.40', '192.168.10.5'

def ip_pkt(t, smac, dmac, src, dst, proto, pl, ttl=64):
    add(t, eth(MAC[smac], MAC[dmac], 0x0800, ipv4(src, dst, proto, pl, ttl)))

def tcp_pkt(t, smac, dmac, src, dst, sp, dp, seq, ack, fl, pl=b'', win=64240, ttl=64):
    o = b'\x02\x04\x05\xb4\x01\x03\x03\x07' if fl & S else b''
    ip_pkt(t, smac, dmac, src, dst, 6, tcp(src, dst, sp, dp, seq, ack, fl, pl, win, o), ttl)

def session(t, cmac, smac, c, s, cp, sp, exchanges, rtt=0.02, ttl_s=56):
    """exchanges: list of (direction 'c'/'s', payload). Full handshake + FIN."""
    cs, ss = random.randint(1, 2**31), random.randint(1, 2**31)
    tcp_pkt(t, cmac, smac, c, s, cp, sp, cs, 0, S); t += rtt
    tcp_pkt(t, smac, cmac, s, c, sp, cp, ss, cs+1, S | A, ttl=ttl_s); t += 0.0005
    cs += 1; ss += 1
    tcp_pkt(t, cmac, smac, c, s, cp, sp, cs, ss, A); t += 0.001
    for d, pl in exchanges:
        if d == 'c':
            tcp_pkt(t, cmac, smac, c, s, cp, sp, cs, ss, P | A, pl); cs += len(pl); t += rtt
            tcp_pkt(t, smac, cmac, s, c, sp, cp, ss, cs, A, ttl=ttl_s)
        else:
            tcp_pkt(t, smac, cmac, s, c, sp, cp, ss, cs, P | A, pl, ttl=ttl_s); ss += len(pl); t += 0.0008
            tcp_pkt(t, cmac, smac, c, s, cp, sp, cs, ss, A)
        t += 0.002
    tcp_pkt(t, cmac, smac, c, s, cp, sp, cs, ss, F | A); t += rtt
    tcp_pkt(t, smac, cmac, s, c, sp, cp, ss, cs+1, F | A, ttl=ttl_s); t += 0.0005
    tcp_pkt(t, cmac, smac, c, s, cp, sp, cs+1, ss+1, A)
    return t

def dns_name(n): return b''.join(bytes([len(p)]) + p.encode() for p in n.split('.')) + b'\0'

def dns_q(tid, name, qtype=1):
    return struct.pack('!HHHHHH', tid, 0x0100, 1, 0, 0, 0) + dns_name(name) + struct.pack('!HH', qtype, 1)

def dns_r(tid, name, qtype=1, answers=(), rcode=0):
    h = struct.pack('!HHHHHH', tid, 0x8180 | rcode, 1, len(answers), 0, 0) + dns_name(name) + struct.pack('!HH', qtype, 1)
    for a in answers:
        if qtype == 1: rd = ip4(a)
        elif qtype == 16: rd = bytes([len(a)]) + a.encode()
        else: rd = dns_name(a)
        h += b'\xc0\x0c' + struct.pack('!HHIH', qtype, 1, 300, len(rd)) + rd
    return h

def dns_exchange(t, name, answers=('93.184.216.34',), qtype=1, rcode=0, delay=0.018, src=CLIENT, smac='client'):
    tid = random.randint(0, 65535); sp = random.randint(49152, 65000)
    ip_pkt(t, smac, 'gw', src, GW, 17, udp(src, GW, sp, 53, dns_q(tid, name, qtype)))
    if delay is not None:
        ip_pkt(t+delay, 'gw', smac, GW, src, 17, udp(GW, src, 53, sp, dns_r(tid, name, qtype, answers if rcode == 0 else (), rcode)))

def client_hello(sni, ver=0x0303):
    ext_sni = struct.pack('!HHHBH', 0, len(sni)+5, len(sni)+3, 0, len(sni)) + sni.encode()
    exts = ext_sni + struct.pack('!HHH', 0x000b, 2, 0x0100)
    body = struct.pack('!H', ver) + bytes(32) + b'\x00' + struct.pack('!H', 4) + b'\x13\x01\xc0\x2f' + b'\x01\x00' + struct.pack('!H', len(exts)) + exts
    hs = b'\x01' + struct.pack('!I', len(body))[1:] + body
    return b'\x16\x03\x01' + struct.pack('!H', len(hs)) + hs

def server_hello(ver=0x0303):
    body = struct.pack('!H', ver) + bytes(32) + b'\x00' + b'\xc0\x2f' + b'\x00' + b'\x00\x00'
    hs = b'\x02' + struct.pack('!I', len(body))[1:] + body
    return b'\x16\x03\x03' + struct.pack('!H', len(hs)) + hs + b'\x17\x03\x03\x00\x40' + bytes(random.getrandbits(8) for _ in range(64))

# ---------- 1. Baseline: ARP, DNS, HTTPS, HTTP ----------
t = 0.0
arp_req = lambda smac, sip, tip: eth(MAC[smac], MAC['bcast'], 0x0806, struct.pack('!HHBBH', 1, 0x0800, 6, 4, 1) + mac(MAC[smac]) + ip4(sip) + bytes(6) + ip4(tip))
arp_rep = lambda smac, sip, dmac, dip: eth(MAC[smac], MAC[dmac], 0x0806, struct.pack('!HHBBH', 1, 0x0800, 6, 4, 2) + mac(MAC[smac]) + ip4(sip) + mac(MAC[dmac]) + ip4(dip))
add(t, arp_req('client', CLIENT, GW)); add(t+0.0004, arp_rep('gw', GW, 'client', CLIENT))

sites = [('www.example.com', '93.184.216.34'), ('login.microsoftonline.com', '20.190.160.10'),
         ('github.com', '140.82.121.4'), ('update.googleapis.com', '142.250.181.99')]
t = 0.5
for name, addr in sites:
    dns_exchange(t, name, (addr,)); t += 0.03
    t = session(t, 'client', 'gw', CLIENT, addr, random.randint(50000, 60000), 443,
                [('c', client_hello(name)), ('s', server_hello()), ('c', b'\x17\x03\x03\x00\x80' + bytes(128)), ('s', b'\x17\x03\x03\x05\x00' + bytes(1280))], rtt=0.035)
    t += 0.4

# plain HTTP with suspicious UA + basic auth
dns_exchange(t, 'intranet.corp.local', ('10.20.0.15',)); t += 0.03
req = (b'GET /admin/config HTTP/1.1\r\nHost: intranet.corp.local\r\nUser-Agent: python-requests/2.31.0\r\n'
       b'Authorization: Basic YWRtaW46UEBzc3cwcmQxMjM=\r\nAccept: */*\r\n\r\n')
rsp = b'HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nContent-Type: text/html\r\nContent-Length: 27\r\n\r\n<html>config portal</html>\n'
t = session(t, 'client', 'gw', CLIENT, '10.20.0.15', 51515, 80, [('c', req), ('s', rsp)], rtt=0.004)
t += 0.2
req2 = b'GET /missing.php HTTP/1.1\r\nHost: intranet.corp.local\r\nUser-Agent: Mozilla/5.0\r\n\r\n'
rsp2 = b'HTTP/1.1 404 Not Found\r\nServer: nginx/1.18.0\r\nContent-Length: 0\r\n\r\n'
t = session(t, 'client', 'gw', CLIENT, '10.20.0.15', 51516, 80, [('c', req2), ('s', rsp2)], rtt=0.004)

# FTP cleartext creds
t += 0.3
t = session(t, 'client', 'gw', CLIENT, '10.20.0.21', 51600, 21,
            [('s', b'220 ProFTPD Server ready.\r\n'), ('c', b'USER backup\r\n'), ('s', b'331 Password required\r\n'),
             ('c', b'PASS Winter2026!\r\n'), ('s', b'230 User backup logged in\r\n'), ('c', b'QUIT\r\n')], rtt=0.003)

# Legacy TLS 1.0
t += 0.3
dns_exchange(t, 'legacy-erp.vendor.example', ('203.0.113.80',)); t += 0.03
t = session(t, 'client', 'gw', CLIENT, '203.0.113.80', 52000, 443, [('c', client_hello('legacy-erp.vendor.example', 0x0301)), ('s', server_hello(0x0301))], rtt=0.06)

# ---------- 2. Slow DNS, NXDOMAIN, unanswered ----------
t += 0.2
dns_exchange(t, 'slow.resolver-test.example', ('198.51.100.7',), delay=1.35); t += 0.1
for n in ['wpad.corp.local', 'printer-old.corp.local', 'fileserver2.corp.local']:
    dns_exchange(t, n, rcode=3); t += 0.05
dns_exchange(t, 'nonresponsive.example.org', delay=None)

# ---------- 3. TCP trouble: retransmissions, dup acks, zero window, RST ----------
t = 8.0
c, s, cp, sp = CLIENT, '10.20.0.30', 53000, 445
cs, ss = 5000, 9000
tcp_pkt(t, 'client', 'gw', c, s, cp, sp, cs, 0, S); t += 0.002
tcp_pkt(t, 'gw', 'client', s, c, sp, cp, ss, cs+1, S | A, ttl=127); t += 0.0003
cs += 1; ss += 1
tcp_pkt(t, 'client', 'gw', c, s, cp, sp, cs, ss, A); t += 0.001
seg = b'\x00' * 1400
for i in range(14):
    tcp_pkt(t, 'client', 'gw', c, s, cp, sp, cs + i*1400, ss, A, seg); t += 0.0005
# server acks only first 3 segments, then dup acks
tcp_pkt(t, 'gw', 'client', s, c, sp, cp, ss, cs + 3*1400, A, ttl=127); t += 0.0002
for _ in range(3):
    tcp_pkt(t, 'gw', 'client', s, c, sp, cp, ss, cs + 3*1400, A, ttl=127); t += 0.0002
# retransmissions
for i in range(3, 7):
    t += 0.21
    tcp_pkt(t, 'client', 'gw', c, s, cp, sp, cs + i*1400, ss, A, seg)
t += 0.01
tcp_pkt(t, 'gw', 'client', s, c, sp, cp, ss, cs + 14*1400, A, win=0, ttl=127); t += 0.3
tcp_pkt(t, 'client', 'gw', c, s, cp, sp, cs + 14*1400 - 1, ss, A, b'\x00'); t += 0.3  # zero window probe
tcp_pkt(t, 'gw', 'client', s, c, sp, cp, ss, cs + 14*1400, A, win=0, ttl=127); t += 0.5
tcp_pkt(t, 'gw', 'client', s, c, sp, cp, ss, cs + 14*1400, R | A, win=0, ttl=127)

# connection refused and timed-out connections
t += 0.2
for port in (8443, 8443):
    p = random.randint(50000, 60000)
    tcp_pkt(t, 'client', 'gw', CLIENT, '10.20.0.31', p, port, 777, 0, S); t += 0.001
    tcp_pkt(t, 'gw', 'client', '10.20.0.31', CLIENT, port, p, 0, 778, R | A, win=0, ttl=63); t += 0.2
p = 50999
for k in range(3):
    tcp_pkt(t + k * (1 + k), 'client', 'gw', CLIENT, '172.16.99.9', p, 3389, 4242, 0, S)

# ---------- 4. Port scan + ping sweep from attacker ----------
t = 14.0
ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 1723, 3306, 3389, 5900, 8080, 8443, 9000, 6379, 27017]
for port in ports:
    sp = random.randint(40000, 65000)
    tcp_pkt(t, 'attacker', 'srv', ATT, SRV, sp, port, 1111, 0, S, win=1024, ttl=64); t += 0.004
    if port in (22, 80, 445, 3389):
        tcp_pkt(t, 'srv', 'attacker', SRV, ATT, port, sp, 2222, 1112, S | A, ttl=128); t += 0.0002
        tcp_pkt(t, 'attacker', 'srv', ATT, SRV, sp, port, 1112, 0, R, win=0); t += 0.002
    else:
        tcp_pkt(t, 'srv', 'attacker', SRV, ATT, port, sp, 0, 1112, R | A, win=0, ttl=128); t += 0.002
t += 0.5
for host in range(100, 116):
    dst = '192.168.10.%d' % host
    icmp = struct.pack('!BBHHH', 8, 0, 0, 0x1234, host) + b'abcdefghijklmnopqrstuvwabcdefghi'
    icmp = icmp[:2] + struct.pack('!H', csum(icmp)) + icmp[4:]
    ip_pkt(t, 'attacker', 'bcast', ATT, dst, 1, icmp); t += 0.01
    if host in (101, 104):
        rep = b'\x00' + icmp[1:]
        rep = rep[:2] + b'\0\0' + rep[4:]; rep = rep[:2] + struct.pack('!H', csum(rep)) + rep[4:]
        ip_pkt(t, 'srv', 'attacker', dst, ATT, 1, rep, ttl=128); t += 0.001
# ICMP unreachable
inner = ipv4(CLIENT, '10.99.1.1', 17, udp(CLIENT, '10.99.1.1', 51000, 161, b'\x30\x26'))[:28]
un = struct.pack('!BBHI', 3, 1, 0, 0) + inner
un = un[:2] + struct.pack('!H', csum(un)) + un[4:]
ip_pkt(t, 'gw', 'client', GW, CLIENT, 1, un)

# ---------- 5. ARP spoofing: attacker claims gateway IP ----------
t = 19.0
for k in range(6):
    add(t + k*1.0, arp_rep('attacker', GW, 'victim', VICTIM))

# ---------- 6. C2-like beaconing + DNS tunnelling ----------
for k in range(12):
    tb = 2.0 + k * 2.0 + random.uniform(-0.03, 0.03)
    session(tb, 'victim', 'gw', VICTIM, '185.220.101.47', 49700 + k, 4444,
            [('c', b'\x00\x00\x00\x10' + bytes(random.getrandbits(8) for _ in range(16))), ('s', b'\x00\x00\x00\x04noop')], rtt=0.09, ttl_s=47)
alphabet = 'abcdefghijklmnopqrstuvwxyz234567'
for k in range(10):
    chunk = ''.join(random.choice(alphabet) for _ in range(52))
    dns_exchange(3.1 + k * 1.7, '%s.%d.exfil-cdn.example' % (chunk, k), ('v=ok',), qtype=16, src=VICTIM, smac='victim')

# ---------- 7. DHCP + rogue DHCP ----------
def dhcp(op, xid, yiaddr, siaddr, chaddr, msgtype, server_id):
    b = struct.pack('!BBBBIHH4s4s4s4s', op, 1, 6, 0, xid, 0, 0x8000, bytes(4), ip4(yiaddr), ip4(siaddr), bytes(4))
    b += mac(chaddr) + bytes(10) + bytes(64) + bytes(128) + b'\x63\x82\x53\x63'
    b += bytes([53, 1, msgtype])
    if server_id: b += bytes([54, 4]) + ip4(server_id)
    b += bytes([12, 7]) + b'LAPTOP7' + b'\xff'
    return b
t = 26.0
add(t, eth(MAC['client'], MAC['bcast'], 0x0800, ipv4('0.0.0.0', '255.255.255.255', 17, udp('0.0.0.0', '255.255.255.255', 68, 67, dhcp(1, 0xabc, '0.0.0.0', '0.0.0.0', MAC['client'], 1, None)))))
add(t+0.01, eth(MAC['gw'], MAC['bcast'], 0x0800, ipv4(GW, '255.255.255.255', 17, udp(GW, '255.255.255.255', 67, 68, dhcp(2, 0xabc, '192.168.10.77', GW, MAC['client'], 2, GW)))))
add(t+0.012, eth(MAC['attacker'], MAC['bcast'], 0x0800, ipv4(ATT, '255.255.255.255', 17, udp(ATT, '255.255.255.255', 67, 68, dhcp(2, 0xabc, '192.168.10.200', ATT, MAC['client'], 2, ATT)))))

# ---------- 8. A bit of IPv6 / mDNS / NTP noise ----------
def ipv6_udp(t, smac, src6, dst6, sp, dp, pl):
    u = struct.pack('!HHHH', sp, dp, 8+len(pl), 0) + pl
    h = struct.pack('!IHBB', 0x60000000, len(u), 17, 255) + src6 + dst6
    add(t, eth(MAC[smac], '33:33:00:00:00:fb', 0x86dd, h + u))
fe80 = bytes.fromhex('fe800000000000003e5282fffe112233'); ff02 = bytes.fromhex('ff0200000000000000000000000000fb')
for k in range(4):
    ipv6_udp(1.5 + k*6, 'client', fe80, ff02, 5353, 5353, dns_q(0, '_airplay._tcp.local', 12))
    ntp = b'\x23' + bytes(47)
    ip_pkt(2.5 + k*6, 'client', 'gw', CLIENT, '162.159.200.1', 17, udp(CLIENT, '162.159.200.1', 123, 123, ntp))

pkts.sort(key=lambda x: x[0])

def write_pcap(path):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for ts, b in pkts:
            sec = int(ts); usec = int(round((ts - sec) * 1e6))
            if usec >= 1000000: sec += 1; usec -= 1000000
            f.write(struct.pack('<IIII', sec, usec, len(b), len(b)) + b)

def write_pcapng(path):
    def blk(t, body):
        pad = (-len(body)) % 4
        L = 12 + len(body) + pad
        return struct.pack('<II', t, L) + body + b'\0'*pad + struct.pack('<I', L)
    out = blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    opt = struct.pack('<HHB3x', 9, 1, 9) + struct.pack('<HH', 0, 0)  # if_tsresol = 9 (ns)
    out += blk(1, struct.pack('<HHI', 1, 0, 65535) + opt)
    for ts, b in pkts:
        ns = int(round(ts * 1e9))
        out += blk(6, struct.pack('<IIIII', 0, ns >> 32, ns & 0xffffffff, len(b), len(b)) + b + b'\0'*((-len(b)) % 4))
    open(path, 'wb').write(out)

write_pcap('samples/sample.pcap'); write_pcapng('samples/sample.pcapng')
print(len(pkts), 'packets')
