#!/usr/bin/env python3
"""Exercise remote SRS download and actual service startup without privileged TUN.
The generated mobile profile's TUN is checked separately. This harness substitutes
an ephemeral local mixed listener; it is not an iOS NetworkExtension test.
"""
import argparse
import functools
import http.server
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time

parser = argparse.ArgumentParser()
parser.add_argument('--core', required=True)
parser.add_argument('--fixture', required=True)
parser.add_argument('--rules', required=True)
parser.add_argument('--large-rules')
args = parser.parse_args()

class Handler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *unused):
        pass

with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    (root / 'rules.srs').write_bytes(Path(args.rules).read_bytes())
    if args.large_rules:
        (root / 'cn.srs').write_bytes(Path(args.large_rules).read_bytes())
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), functools.partial(Handler, directory=directory))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    config = json.loads(Path(args.fixture).read_text())
    assert any(i['type'] == 'tun' for i in config['inbounds']), 'Mobile profile lacks TUN'
    assert config['dns']['final'] == 'dns-remote', 'Mobile DNS changed to direct'
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        port = listener.getsockname()[1]
    config['inbounds'] = [{'type': 'mixed', 'listen': '127.0.0.1', 'listen_port': port}]
    config['log'] = {'level': 'info', 'timestamp': False}
    config['route']['auto_detect_interface'] = False  # allow local test resource server
    for rule_set in config['route']['rule_set']:
        path = 'cn.srs' if args.large_rules and rule_set['tag'] == 'CN_域' else 'rules.srs'
        rule_set.update(type='remote', format='binary', url=f'http://127.0.0.1:{server.server_port}/{path}', download_detour='🇨🇳 大陆')
    # Disable platform-specific cache files in this isolated test directory.
    config.pop('experimental', None)
    profile = root / 'profile.json'
    profile.write_text(json.dumps(config), encoding='utf-8')
    log_path = root / 'service.log'
    env = dict(os.environ, GOMEMLIMIT='40MiB', GOGC='20')
    with log_path.open('w') as logs:
        process = subprocess.Popen([args.core, 'run', '-c', str(profile)], cwd=directory, stdout=logs, stderr=logs, env=env)
        started = False
        peak_kb = 0
        try:
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise RuntimeError('Service exited during startup:\n' + log_path.read_text())
                try:
                    for line in Path(f'/proc/{process.pid}/status').read_text().splitlines():
                        if line.startswith('VmHWM:'):
                            peak_kb = max(peak_kb, int(line.split()[1]))
                except FileNotFoundError:
                    pass
                text = log_path.read_text()
                if 'sing-box started' in text:
                    started = True
                    with socket.create_connection(('127.0.0.1', port), timeout=1) as connection:
                        connection.sendall(b'\x05\x01\x00')
                        assert connection.recv(2) == b'\x05\x00', 'Mixed listener cannot accept proxy connections'
                    time.sleep(0.3)
                    break
                time.sleep(0.02)
            if not started:
                raise RuntimeError('Startup timed out:\n' + log_path.read_text())
            if process.poll() is not None:
                raise RuntimeError('Service exited after startup:\n' + log_path.read_text())
            print(f'Remote SRS download, startup, and proxy listener passed; Linux RSS peak {peak_kb} KiB (not an iOS memory measurement)')
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            server.shutdown()
