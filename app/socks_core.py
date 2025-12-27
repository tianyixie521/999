#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
socks_core.py - Android/跨平台可复用的 SOCKS5 测试核心（无GUI依赖）

从原 Tkinter 版本中抽离网络/协议逻辑（SOCKS5 握手、连接、收发、分块发送、回显服务器）。
可被：
- Termux/Pydroid 直接运行的 CLI 调用
- Kivy/Chaquopy/原生 Android UI 调用

注意：
- 所有日志通过 logger 回调输出，方便接 UI。
"""

from __future__ import annotations

import socket
import struct
import time
import threading
import hashlib
from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Optional, Tuple, List


Logger = Callable[[str], None]


# ---------------------------- 工具函数 ----------------------------
def now_hms() -> str:
    return datetime.now().strftime("%H:%M:%S")


def md5_hex(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def to_hex(data: bytes, per_line: int = 16) -> str:
    if not data:
        return ""
    out = []
    for i in range(0, len(data), per_line):
        chunk = data[i:i + per_line]
        out.append(" ".join(f"{b:02X}" for b in chunk))
    return "\n".join(out)


def parse_hex_string(hex_str: str) -> bytes:
    s = hex_str.strip().replace("0x", "").replace("0X", "")
    s = s.replace(" ", "").replace("\n", "").replace("\r", "").replace("\t", "")
    if not s:
        return b""
    if len(s) % 2 != 0:
        raise ValueError("十六进制字符串长度必须为偶数")
    try:
        return bytes(int(s[i:i + 2], 16) for i in range(0, len(s), 2))
    except ValueError as e:
        raise ValueError(f"无效的十六进制字符: {e}") from e


def chunk_bytes(payload: bytes, chunk_size: int) -> List[bytes]:
    if chunk_size <= 0:
        raise ValueError("chunk_size 必须 > 0")
    return [payload[i:i + chunk_size] for i in range(0, len(payload), chunk_size)]


# ---------------------------- SOCKS5 协议 ----------------------------
def _encode_address(host: str) -> Tuple[int, bytes]:
    """返回 (ATYP, ADDR_BYTES)"""
    try:
        return 0x01, socket.inet_aton(host)  # IPv4
    except OSError:
        host_bytes = host.encode("idna")
        if len(host_bytes) > 255:
            raise ValueError("域名过长")
        return 0x03, bytes([len(host_bytes)]) + host_bytes


def socks5_auth_negotiate(sock: socket.socket, username: Optional[str], password: Optional[str]) -> bool:
    """
    协商认证方式：
    - 无账号：只尝试 0x00（无认证）
    - 有账号：提供 0x00 与 0x02（用户名密码）两种方式，接受服务端选择
    """
    try:
        if username and password:
            methods = b"\x00\x02"
            sock.sendall(b"\x05" + bytes([len(methods)]) + methods)
            resp = sock.recv(2)
            if len(resp) != 2 or resp[0] != 0x05:
                return False
            method = resp[1]
            if method == 0x00:
                return True
            if method != 0x02:
                return False

            u = username.encode("utf-8")
            p = password.encode("utf-8")
            if len(u) > 255 or len(p) > 255:
                return False
            # RFC1929
            sock.sendall(b"\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p)
            auth_resp = sock.recv(2)
            return len(auth_resp) == 2 and auth_resp[1] == 0x00

        # 无认证
        sock.sendall(b"\x05\x01\x00")
        resp = sock.recv(2)
        return resp == b"\x05\x00"
    except Exception:
        return False


def socks5_connect(sock: socket.socket, target_host: str, target_port: int) -> int:
    """
    发送 CONNECT 请求并读取响应，返回 REP(reply_code)。
    """
    atyp, addr = _encode_address(target_host)
    req = b"\x05\x01\x00" + bytes([atyp]) + addr + struct.pack(">H", target_port)
    sock.sendall(req)

    header = sock.recv(4)
    if len(header) < 4:
        raise OSError("SOCKS5 响应头过短")
    ver, rep, rsv, atyp2 = header
    if ver != 0x05:
        raise OSError("不支持的 SOCKS 版本")

    # 读 BND.ADDR
    if atyp2 == 0x01:
        sock.recv(4)
    elif atyp2 == 0x03:
        ln = sock.recv(1)
        if not ln:
            raise OSError("SOCKS5 域名长度缺失")
        sock.recv(ln[0])
    elif atyp2 == 0x04:
        sock.recv(16)
    else:
        raise OSError(f"不支持的地址类型: 0x{atyp2:02x}")

    sock.recv(2)  # BND.PORT
    return rep


# ---------------------------- 回显服务器（可选） ----------------------------
class EchoServer:
    """
    简单 TCP 回显服务器：收到数据后原样回显。
    Termux 上可用于自测；打包为 Android App 时也可用，但需网络权限。
    """

    def __init__(self, host: str, port: int, logger: Optional[Logger] = None):
        self.host = host
        self.port = port
        self.logger = logger or (lambda _: None)
        self._sock: Optional[socket.socket] = None
        self._t: Optional[threading.Thread] = None
        self._running = threading.Event()

    def start(self) -> None:
        if self._running.is_set():
            self.logger("[i] 回显服务器已在运行")
            return
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self._sock.listen(5)
        self._sock.settimeout(1.0)
        self._running.set()
        self._t = threading.Thread(target=self._loop, daemon=True)
        self._t.start()
        self.logger(f"[+] 回显服务器启动: {self.host}:{self.port}")

    def stop(self) -> None:
        self._running.clear()
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
        self.logger("[i] 回显服务器停止")

    def _loop(self) -> None:
        assert self._sock is not None
        while self._running.is_set():
            try:
                cs, addr = self._sock.accept()
            except socket.timeout:
                continue
            except Exception:
                break
            threading.Thread(target=self._handle, args=(cs, addr), daemon=True).start()

    def _handle(self, cs: socket.socket, addr):
        try:
            cs.settimeout(10.0)
            data = cs.recv(4096)
            if data:
                self.logger(f"[+] 收到 {addr[0]}:{addr[1]} {len(data)} 字节 MD5={md5_hex(data)}")
                cs.sendall(data)
        except Exception as e:
            self.logger(f"[!] 客户端处理异常: {e}")
        finally:
            try:
                cs.close()
            except Exception:
                pass


# ---------------------------- 测试器 ----------------------------
SOCKS5_REP_MSG = {
    0x00: "成功",
    0x01: "常规 SOCKS 服务器失败",
    0x02: "不允许的连接",
    0x03: "网络不可达",
    0x04: "主机不可达",
    0x05: "连接被拒绝",
    0x06: "TTL 过期",
    0x07: "命令不支持",
    0x08: "地址类型不支持",
}


@dataclass
class SocksConfig:
    proxy_host: str
    proxy_port: int
    username: Optional[str] = None
    password: Optional[str] = None


@dataclass
class TargetConfig:
    host: str
    port: int


class Socks5Tester:
    def __init__(self, logger: Optional[Logger] = None):
        self.log = logger or (lambda _: None)

    def _connect_once(self, socks: SocksConfig, target: TargetConfig, timeout: int) -> socket.socket:
        self.log(f"[{now_hms()}] [1/3] 连接代理 {socks.proxy_host}:{socks.proxy_port}")
        s = socket.create_connection((socks.proxy_host, socks.proxy_port), timeout=10)
        s.settimeout(timeout)

        self.log(f"[{now_hms()}] [2/3] SOCKS5 协商")
        if not socks5_auth_negotiate(s, socks.username, socks.password):
            s.close()
            raise OSError("SOCKS5 认证/协商失败")

        self.log(f"[{now_hms()}] [3/3] CONNECT {target.host}:{target.port}")
        rep = socks5_connect(s, target.host, target.port)
        if rep != 0x00:
            s.close()
            raise OSError(f"SOCKS5 连接失败: {SOCKS5_REP_MSG.get(rep, hex(rep))}")
        return s

    def test_once(self, socks: SocksConfig, target: TargetConfig, payload: bytes, timeout: int = 30) -> bytes:
        """
        单连接发送一次 payload，尽量读回响应（直到短超时或对端关闭）。
        """
        s: Optional[socket.socket] = None
        try:
            s = self._connect_once(socks, target, timeout=timeout)

            if payload:
                self.log(f"[{now_hms()}] 发送 {len(payload)} 字节 MD5={md5_hex(payload)}")
                s.sendall(payload)
            else:
                self.log(f"[{now_hms()}] payload 为空，跳过发送")

            resp = self._recv_all(s, overall_timeout=10)
            if resp:
                self.log(f"[{now_hms()}] 收到 {len(resp)} 字节 MD5={md5_hex(resp)}")
            else:
                self.log(f"[{now_hms()}] 未收到响应")
            return resp
        finally:
            if s:
                try:
                    s.close()
                except Exception:
                    pass

    def test_chunked(
        self,
        socks: SocksConfig,
        target: TargetConfig,
        chunks: List[bytes],
        interval_sec: float = 0.1,
        timeout_per_conn: int = 30,
        progress_cb: Optional[Callable[[int, int, bytes], None]] = None,
    ) -> bytes:
        """
        分块发送：每个 chunk 使用独立 SOCKS 连接（与原脚本一致）。
        progress_cb(current, total, all_responses)
        """
        all_resp = b""
        ok = 0
        fail = 0

        for idx, chunk in enumerate(chunks, start=1):
            start = time.time()
            s: Optional[socket.socket] = None
            try:
                self.log(f"[{now_hms()}] [→] 第 {idx}/{len(chunks)} 块 {len(chunk)} 字节")
                s = self._connect_once(socks, target, timeout=timeout_per_conn)
                s.sendall(chunk)

                resp = self._recv_all(s, overall_timeout=10)
                if resp:
                    ok += 1
                    all_resp += resp
                    self.log(f"[{now_hms()}] [✓] 第 {idx} 块响应 {len(resp)} 字节，用时 {time.time()-start:.3f}s")
                else:
                    fail += 1
                    self.log(f"[{now_hms()}] [!] 第 {idx} 块无响应，用时 {time.time()-start:.3f}s")

                if progress_cb:
                    progress_cb(idx, len(chunks), all_resp)

            except Exception as e:
                fail += 1
                self.log(f"[{now_hms()}] [!] 第 {idx} 块失败: {e}")
                if progress_cb:
                    progress_cb(idx, len(chunks), all_resp)
            finally:
                if s:
                    try:
                        s.close()
                    except Exception:
                        pass

            if idx < len(chunks) and interval_sec > 0:
                time.sleep(interval_sec)

        self.log(f"[{now_hms()}] 完成：成功 {ok}/{len(chunks)} 失败 {fail}")
        return all_resp

    def _recv_all(self, s: socket.socket, overall_timeout: int = 10) -> bytes:
        """
        接收尽量多的数据：用短超时循环，收到数据后稍微延长窗口。
        """
        data = b""
        s.settimeout(1.0)
        end = time.time() + overall_timeout
        while time.time() < end:
            try:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
                end = time.time() + 2  # 收到数据后给多一点时间收尾包
            except socket.timeout:
                if data:
                    break
            except Exception:
                break
        return data
