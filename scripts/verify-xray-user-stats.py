"""Measure Xray's SOCKS5 counters inside a disposable Linux network namespace."""

import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
from socketserver import BaseRequestHandler, ThreadingTCPServer
import stat
import struct
import subprocess
from tempfile import TemporaryDirectory
from threading import Event, Thread
import time
from zipfile import ZipFile


RELEASE_SHA256 = "e4bd9119f50ae7c41658b1abd0679ae06f98bd864a2907ff33f2f2cf7081b214"
TARGET = "93.184.216.34"
TARGET_PORT = 28080
PORTS = (27810, 27811)
PASSWORDS = {"alice": "A" * 43, "bob": "E" * 43}
UPLOAD = b"u" * 262147
DOWNLOAD = b"d" * 1048583


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def read_exact(conn, size):
    result = bytearray()
    while len(result) < size:
        chunk = conn.recv(size - len(result))
        require(chunk, "unexpected end of stream")
        result.extend(chunk)
    return result


class DataEndpoint(BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        require(read_exact(self.request, len(UPLOAD)) == UPLOAD, "target received incorrect bytes")
        self.request.sendall(DOWNLOAD)
        self.server.finish_transfer.wait(10)


@contextmanager
def tunnel(port, username, accepted=True):
    with socket.create_connection(("127.0.0.1", port), timeout=5) as conn:
        conn.sendall(b"\x05\x01\x02")
        require(read_exact(conn, 2) == b"\x05\x02", "SOCKS5 password negotiation failed")
        name = username.encode()
        password = PASSWORDS[username].encode()
        conn.sendall(bytes([1, len(name)]) + name + bytes([len(password)]) + password)
        reply = read_exact(conn, 2)
        if not accepted:
            require(reply == b"\x01\xff", "unauthorized user authenticated")
            yield None
            return
        require(reply == b"\x01\x00", "authorized user was rejected")
        conn.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(TARGET) + struct.pack("!H", TARGET_PORT))
        require(read_exact(conn, 4) == b"\x05\x00\x00\x01", "SOCKS5 CONNECT failed")
        read_exact(conn, 6)
        conn.sendall(UPLOAD)
        require(read_exact(conn, len(DOWNLOAD)) == DOWNLOAD, "client received incorrect bytes")
        yield conn


def build_config(socket_path):
    inbounds = []
    for port, users in zip(PORTS, (("alice", "bob"), ("bob",)), strict=True):
        inbounds.append({
            "listen": "127.0.0.1", "port": port, "protocol": "socks", "tag": f"socks-{port}",
            "settings": {
                "auth": "password", "udp": False,
                "users": [{"user": name, "pass": PASSWORDS[name]} for name in users],
            },
        })
    return {
        "log": {"loglevel": "warning"},
        "api": {"tag": "stats", "listen": f"{socket_path},0600", "services": ["StatsService"]},
        "stats": {},
        "policy": {"levels": {"0": {"statsUserUplink": True, "statsUserDownlink": True}}},
        "inbounds": inbounds,
        "outbounds": [
            {"protocol": "blackhole", "tag": "deny"}, {"protocol": "freedom", "tag": "allowed"},
        ],
        "routing": {"domainStrategy": "AsIs", "rules": [{
            "inboundTag": [entry["tag"] for entry in inbounds], "network": "tcp",
            "ip": [TARGET + "/32"], "port": TARGET_PORT, "outboundTag": "allowed",
        }]},
    }


def read_stats(binary, socket_path):
    result = subprocess.run(
        [binary, "api", "statsquery", "-s", f"unix://{socket_path}", "-t", "2", "-pattern", "user>>>"],
        check=True, capture_output=True, timeout=4,
    )
    counters = {}
    for sample in json.loads(result.stdout).get("stat", []):
        name = sample["name"]
        require(name not in counters, "duplicate counter name")
        counters[name] = int(sample.get("value", 0))
    return counters


def totals(counters, username):
    return [
        counters.get(f"user>>>{username}>>>traffic>>>uplink", 0),
        counters.get(f"user>>>{username}>>>traffic>>>downlink", 0),
    ]


@contextmanager
def run_xray(binary, socket_path, splice):
    env = os.environ | {"xray.buf.splice": splice}
    config_path = socket_path.parent / "config.json"
    log_path = socket_path.parent / "xray.log"
    config_path.write_text(json.dumps(build_config(socket_path)), encoding="utf-8")
    with log_path.open("wb") as log, config_path.open("rb") as config:
        process = subprocess.Popen([binary, "run", "-config", "stdin:"], stdin=config, stdout=log, stderr=log, env=env)
        try:
            for _ in range(100):
                if process.poll() is not None:
                    raise RuntimeError(log_path.read_text(encoding="utf-8"))
                if socket_path.exists():
                    mode = socket_path.stat().st_mode
                    if stat.S_ISSOCK(mode) and stat.S_IMODE(mode) == 0o600:
                        break
                time.sleep(0.05)
            else:
                raise RuntimeError("private Xray statistics socket did not become ready")
            yield process
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


def after_transfer(binary, stats_socket, user):
    expected = [len(UPLOAD), len(DOWNLOAD)]
    for _ in range(25):
        current = totals(read_stats(binary, stats_socket), user)
        if current == expected:
            return current
        time.sleep(0.04)
    raise RuntimeError(f"{user} totals after close: {current}, expected {expected}")


def measure(binary, work):
    result = {}
    with ThreadingTCPServer((TARGET, TARGET_PORT), DataEndpoint) as endpoint:
        worker = Thread(target=endpoint.serve_forever, daemon=True)
        worker.start()
        try:
            for splice in ("auto", "disable"):
                endpoint.finish_transfer = Event()
                stats_socket = work / f"{splice}.sock"
                with run_xray(binary, stats_socket, splice):
                    require(read_stats(binary, stats_socket) == {}, "fresh process reported pre-existing usage")
                    with tunnel(PORTS[1], "alice", accepted=False):
                        pass
                    require(read_stats(binary, stats_socket) == {}, "rejected authentication changed counters")
                    with tunnel(PORTS[0], "alice"):
                        first = read_stats(binary, stats_socket)
                        require(first == read_stats(binary, stats_socket), "repeated stats reads changed totals")
                        require(totals(first, "bob") == [0, 0], "Alice's traffic was charged to Bob")
                        result[splice + "_open"] = totals(first, "alice")
                        endpoint.finish_transfer.set()
                    result[splice + "_closed"] = after_transfer(binary, stats_socket, "alice")
                    endpoint.finish_transfer = Event()
                    with tunnel(PORTS[1], "bob"):
                        endpoint.finish_transfer.set()
                    result[splice + "_bob"] = after_transfer(binary, stats_socket, "bob")
                    require(totals(read_stats(binary, stats_socket), "alice") == result[splice + "_closed"],
                            "Bob's traffic changed Alice's closed totals")
            with run_xray(binary, work / "restarted.sock", "disable"):
                result["after_restart"] = read_stats(binary, work / "restarted.sock")
        finally:
            endpoint.shutdown()
            worker.join(timeout=5)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path, help="official Xray v26.10.31 Xray-linux-64.zip")
    args = parser.parse_args()
    require(set(name for _, name in socket.if_nameindex()) == {"lo"}, "run in a loopback-only Linux network namespace")
    with args.archive.open("rb") as archive:
        require(hashlib.file_digest(archive, "sha256").hexdigest() == RELEASE_SHA256, "unexpected Xray archive SHA-256")
        archive.seek(0)
        with TemporaryDirectory(prefix="mcui-stats-") as temp, ZipFile(archive) as zip_file:
            work = Path(temp)
            binary = work / "xray"
            with zip_file.open("xray") as src, binary.open("xb") as output:
                shutil.copyfileobj(src, output)
            binary.chmod(0o700)
            result = measure(binary, work)

    print(json.dumps(result, sort_keys=True))
    require(result["auto_open"][0] == len(UPLOAD) and result["auto_open"][1] < len(DOWNLOAD),
            "default splice behavior changed; review live downlink accounting")
    require(result["disable_open"] == [len(UPLOAD), len(DOWNLOAD)],
            "splice-disabled counters did not cover the open tunnel")
    require(result["after_restart"] == {}, "counter restart behavior changed")


if __name__ == "__main__":
    main()
