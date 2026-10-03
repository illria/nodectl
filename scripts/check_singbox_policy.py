#!/usr/bin/env python3
"""Exercise generated domestic/overseas routing and DNS with real sing-box cores.

All endpoints are loopback mocks; TLS/proxy protocol compatibility and remote
SRS startup are checked separately. TUN is replaced by SOCKS, not an iOS test.
"""
import argparse
import contextlib
import http.server
import json
import os
from pathlib import Path
import select
import socket
import socketserver
import struct
import subprocess
import tempfile
import threading
import time
import urllib.request


def read_exact(connection, count):
    result = b''
    while len(result) < count:
        chunk = connection.recv(count - len(result))
        if not chunk:
            raise EOFError('Connection closed')
        result += chunk
    return result


class Server(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


class DNS(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        try:
            while True:
                query = read_exact(self.request, struct.unpack('!H', read_exact(self.request, 2))[0])
                offset, labels = 12, []
                while query[offset]:
                    length = query[offset]
                    labels.append(query[offset + 1:offset + 1 + length].decode())
                    offset += length + 1
                end = offset + 5
                name = '.'.join(labels).lower()
                kind = struct.unpack('!H', query[offset + 1:offset + 3])[0]
                self.server.queries.append(name)
                self.server.questions.append((name, kind))
                answer = b''
                if kind == 1:
                    answer = b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 60, 4) + socket.inet_aton(self.server.answer)
                elif kind == 28:
                    answer = b'\xc0\x0c' + struct.pack('!HHIH', 28, 1, 60, 16) + socket.inet_pton(socket.AF_INET6, self.server.answer6)
                elif kind in (64, 65):
                    # SVCB/HTTPS priority 1, root target, ipv6hint parameter.
                    data = b'\x00\x01\x00' + struct.pack('!HH', 6, 16) + socket.inet_pton(socket.AF_INET6, self.server.answer6)
                    answer = b'\xc0\x0c' + struct.pack('!HHIH', kind, 1, 60, len(data)) + data
                response = query[:2] + struct.pack('!HHHHH', 0x8180, 1, int(bool(answer)), 0, 0) + query[12:end] + answer
                self.request.sendall(struct.pack('!H', len(response)) + response)
        except (EOFError, OSError):
            pass


class Website(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'policy-ok'
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *unused):
        pass


class Proxy(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        with contextlib.ExitStack() as stack:
            headers = b''
            while not headers.endswith(b'\r\n\r\n'):
                headers += read_exact(self.request, 1)
                if len(headers) > 8192:
                    raise ValueError('Oversized proxy headers')
            method, target, _ = headers.split(b'\r\n', 1)[0].decode().split()
            assert method == 'CONNECT', method
            host, port = target.rsplit(':', 1)
            port = int(port)
            # Never open an external connection, even for the overseas test name.
            assert port in self.server.allowed_ports, target
            self.server.connections.append((host, port))
            destination = stack.enter_context(socket.create_connection(('127.0.0.1', port), timeout=5))
            self.request.sendall(b'HTTP/1.1 200 Connection established\r\n\r\n')
            while True:
                readable, _, _ = select.select([self.request, destination], [], [], 5)
                if not readable:
                    return
                for source in readable:
                    data = source.recv(65536)
                    if not data:
                        return
                    (destination if source is self.request else self.request).sendall(data)


def start(server):
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def unused_port():
    with socket.socket() as connection:
        connection.bind(('127.0.0.1', 0))
        return connection.getsockname()[1]


def socks_connection(port, host, destination_port, payload):
    connection = socket.create_connection(('127.0.0.1', port), timeout=5)
    try:
        connection.sendall(b'\x05\x01\x00')
        assert read_exact(connection, 2) == b'\x05\x00'
        try:
            address = b'\x01' + socket.inet_aton(host)
        except OSError:
            address = b'\x03' + bytes([len(host)]) + host.encode()
        # Complete standard SOCKS negotiation before sending application data.
        connection.sendall(b'\x05\x01\x00' + address + struct.pack('!H', destination_port))
        reply = read_exact(connection, 4)
        assert reply[:2] == b'\x05\x00', (host, reply)
        if reply[3] == 1:
            read_exact(connection, 6)
        elif reply[3] == 4:
            read_exact(connection, 18)
        else:
            read_exact(connection, read_exact(connection, 1)[0] + 2)
        connection.sendall(payload)
        return connection
    except BaseException:
        connection.close()
        raise


def dns_query(port, host, kind=1):
    name = b''.join(bytes([len(label)]) + label.encode() for label in host.split('.')) + b'\x00'
    query = struct.pack('!HHHHHH', 42, 0x0100, 1, 0, 0, 0) + name + struct.pack('!HH', kind, 1)
    with socks_connection(port, '8.8.8.8', 53, struct.pack('!H', len(query)) + query) as connection:
        response = read_exact(connection, struct.unpack('!H', read_exact(connection, 2))[0])
    assert response[:2] == query[:2] and response[3] & 15 == 0, response
    count = struct.unpack('!H', response[6:8])[0]
    if count == 0:
        return None
    assert count == 1, response
    ipv6 = kind in (28, 64, 65)
    return socket.inet_ntop(socket.AF_INET6 if ipv6 else socket.AF_INET, response[-16:] if ipv6 else response[-4:])


def visit(port, host, website_port):
    payload = f'GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n'.encode()
    with socks_connection(port, host, website_port, payload) as connection:
        response = b''
        while b'policy-ok' not in response:
            response += read_exact(connection, 1)
    assert b'200 OK' in response


parser = argparse.ArgumentParser()
parser.add_argument('--core', required=True)
parser.add_argument('--fixture', required=True)
args = parser.parse_args()
fixture = Path(args.fixture)
config = json.loads(fixture.read_text())
minor = int(fixture.name.split('.')[1].split('-')[0])
assert config['dns']['final'] == 'dns-remote'
assert any(i['type'] == 'tun' for i in config['inbounds'])

direct = Server(('127.0.0.1', 0), DNS)
direct.queries, direct.answer = [], '127.0.0.1'
direct.questions, direct.answer6 = [], '2001:db8::1'
remote = Server(('127.0.0.1', 0), DNS)
remote.queries, remote.answer = [], '127.0.0.2'
remote.questions, remote.answer6 = [], '2001:db8::2'
website = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Website)
proxy = Server(('127.0.0.1', 0), Proxy)
proxy.connections = []
proxy.allowed_ports = {direct.server_address[1], remote.server_address[1], website.server_port}
servers = [start(s) for s in [direct, remote, website, proxy]]

try:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        port, controller = unused_port(), unused_port()
        config['inbounds'] = [{'type': 'mixed', 'listen': '127.0.0.1', 'listen_port': port}]
        config['log'] = {'level': 'debug'}
        config['route']['auto_detect_interface'] = False
        (root / 'empty-domain.json').write_text('{"version":1,"rules":[{"domain":["unused-fixture.invalid"]}]}')
        domestic_dns_sets = {tag for rule in config['dns']['rules'] if rule.get('server') == 'dns-bootstrap' for tag in rule.get('rule_set', [])}
        for rule_set in config['route']['rule_set']:
            name = 'cn.srs' if rule_set['tag'] == 'CN_域' else 'domestic-module.srs' if rule_set['tag'] == 'BiliBili_域' else 'rules.srs'
            tag = rule_set['tag']
            rule_set.clear()
            rule_set.update(type='local', tag=tag, format='binary', path=str((fixture.parent / name).resolve()))
            if tag in domestic_dns_sets and tag not in ['CN_域', 'BiliBili_域']:
                # Domain providers must not use the generic IP/port fixture:
                # those conditions cause response-filter DNS lookups on 1.9+.
                rule_set.update(format='source', path=str(root / 'empty-domain.json'))
        for outbound in config['outbounds']:
            if outbound['tag'] == '总模式':
                outbound.update(outbounds=['policy-proxy'], default='policy-proxy')
            elif outbound['type'] == 'urltest':
                outbound['type'] = 'selector'
                outbound['default'] = outbound['outbounds'][0]
                for key in ['url', 'interval', 'tolerance']:
                    outbound.pop(key, None)
        config['outbounds'].append({'type': 'http', 'tag': 'policy-proxy', 'server': '127.0.0.1', 'server_port': proxy.server_address[1]})
        for server in config['dns']['servers']:
            tag = server['tag']
            if tag == 'dns-ipv4-compat':
                assert server['address'] == 'rcode://success', 'IPv4 hint rule must not access another DNS server'
                continue
            direct_detour = server.get('detour', '🇨🇳 大陆')
            assert server.get('type', 'https') == 'https', 'Generated DNS must stay encrypted'
            assert tag != 'dns-remote' or server['detour'] == '总模式'
            server.clear()
            server['tag'] = tag
            mock = remote if tag == 'dns-remote' else direct
            if minor >= 12:
                server.update(type='tcp', server='127.0.0.1', server_port=mock.server_address[1])
            else:
                server['address'] = f'tcp://127.0.0.1:{mock.server_address[1]}'
            if tag == 'dns-remote':
                server['detour'] = '总模式'
            elif minor < 12:
                server['detour'] = direct_detour
        config['experimental'] = {'clash_api': {'external_controller': f'127.0.0.1:{controller}', 'default_mode': 'Rule'}}
        profile = root / 'profile.json'
        profile.write_text(json.dumps(config))
        log = root / 'service.log'
        with log.open('w') as logs:
            process = subprocess.Popen([args.core, 'run', '-c', str(profile)], stdout=logs, stderr=logs, cwd=directory, env=dict(os.environ, GOMEMLIMIT='40MiB', GOGC='20'))
            try:
                deadline = time.monotonic() + 20
                while 'sing-box started' not in log.read_text():
                    assert process.poll() is None, log.read_text()
                    assert time.monotonic() < deadline, 'Startup timeout'
                    time.sleep(0.05)

                def mode(name):
                    req = urllib.request.Request(f'http://127.0.0.1:{controller}/configs', data=json.dumps({'mode': name}).encode(), headers={'Content-Type': 'application/json'}, method='PATCH')
                    with urllib.request.urlopen(req, timeout=3) as response:
                        assert response.status == 204

                def check(host, expected, proxied):
                    assert dns_query(port, host) == expected, (host, 'wrong DNS server or cross-mode cache')
                    queries_before = len(direct.questions) + len(remote.questions)
                    expected6 = (remote if proxied else direct).answer6 if config['dns']['strategy'] != 'ipv4_only' else None
                    for kind in [28, 64, 65]:
                        assert dns_query(port, host, kind) == expected6, (host, kind, 'wrong AAAA/SVCB/HTTPS address policy')
                    if expected6 is None:
                        assert len(direct.questions) + len(remote.questions) == queries_before, (host, 'IPv4-only mode sent an upstream AAAA query')
                    assert expected != direct.answer or host not in remote.queries, (host, 'domestic DNS crossed proxy')
                    before = len([c for c in proxy.connections if c[1] == website.server_port])
                    visit(port, host, website.server_port)
                    after = len([c for c in proxy.connections if c[1] == website.server_port])
                    assert after - before == int(proxied), (host, 'wrong traffic outbound')

                domestic = ['lf3-cdn-tos.bytecdntp.com', 'i0.hdslb.com', 'res.wx.qq.com', 'g.alicdn.com', 'domestic-module.test']
                for host in domestic:
                    check(host, direct.answer, False)
                check('unmatched-overseas.test', remote.answer, True)
                assert 'unmatched-overseas.test' not in direct.queries, 'Overseas DNS leaked to domestic resolver'
                mode('Global')
                assert dns_query(port, domestic[0], 28) == (None if config['dns']['strategy'] == 'ipv4_only' else remote.answer6), 'Global has wrong AAAA policy'
                assert dns_query(port, domestic[0]) == remote.answer, 'Global reused direct DNS cache'
                before = len([c for c in proxy.connections if c[1] == website.server_port])
                visit(port, domestic[0], website.server_port)
                assert len([c for c in proxy.connections if c[1] == website.server_port]) == before + 1, 'Global did not use proxy'
                mode('Direct')
                assert dns_query(port, 'unmatched-overseas.test', 28) == (None if config['dns']['strategy'] == 'ipv4_only' else direct.answer6), 'Direct has wrong AAAA policy'
                assert dns_query(port, 'unmatched-overseas.test') == direct.answer, 'Direct reused proxy DNS cache'
                before = len(proxy.connections)
                visit(port, 'unmatched-overseas.test', website.server_port)
                assert len(proxy.connections) == before, 'Direct used proxy'
                mode('Rule')
                assert dns_query(port, domestic[0]) == direct.answer, 'Rule reused Global DNS cache'
                print(f'Domestic CDN and app-selector traffic/DNS direct; overseas traffic/DNS proxy; cross-mode DNS cache isolation; A/AAAA/HTTPS/SVCB {config["dns"]["strategy"]} policy passed')
            except BaseException:
                print(log.read_text())
                raise
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
finally:
    for server in servers:
        server.shutdown()
        server.server_close()
