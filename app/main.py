# -*- coding: utf-8 -*-
"""
kivy_app.py - Kivy 版 Android GUI（核心功能可用，界面精简）

说明：
- 这是“可打包成 APK”的方向（用 Buildozer / python-for-android）。
- UI 尽量做成单屏：代理配置、目标、Hex、发送、分块发送、日志、结果摘要。
- Android 打包需在 buildozer.spec 添加权限：INTERNET

依赖：
pip install kivy
（注意：Windows 上开发可运行；打包 APK 建议在 Linux/WSL）
"""

from __future__ import annotations

import threading

from kivy.app import App
from kivy.clock import Clock
from kivy.metrics import dp
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.gridlayout import GridLayout
from kivy.uix.label import Label
from kivy.uix.scrollview import ScrollView
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button

from socks_core import Socks5Tester, SocksConfig, TargetConfig, parse_hex_string, to_hex, md5_hex, chunk_bytes


class LogView(TextInput):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.readonly = True
        self.multiline = True
        self.font_size = "12sp"


class Root(BoxLayout):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.orientation = "vertical"
        self.padding = dp(8)
        self.spacing = dp(6)

        self.tester = Socks5Tester(logger=self._log)

        # ---- form ----
        form = GridLayout(cols=2, spacing=dp(6), size_hint_y=None)
        form.bind(minimum_height=form.setter("height"))

        def add_row(title: str, default: str, password=False):
            form.add_widget(Label(text=title, size_hint_x=0.35, halign="right", valign="middle"))
            ti = TextInput(text=default, multiline=False, password=password)
            form.add_widget(ti)
            return ti

        self.proxy_host = add_row("代理Host", "")
        self.proxy_port = add_row("代理Port", "1080")
        self.proxy_user = add_row("用户名(可空)", "")
        self.proxy_pass = add_row("密码(可空)", "", password=True)
        self.target_host = add_row("目标Host", "127.0.0.1")
        self.target_port = add_row("目标Port", "36000")
        self.chunk_size = add_row("分块大小", "1024")
        self.interval = add_row("块间隔(秒)", "0.1")

        self.add_widget(form)

        # ---- hex input ----
        self.hex_in = TextInput(
            text="01 0A 00 09 32 19 00 00 04 30 24 E6 89 97 00 00",
            size_hint_y=None,
            height=dp(120),
            multiline=True,
            font_size="12sp"
        )
        self.add_widget(Label(text="发送Hex（空格/换行均可）", size_hint_y=None, height=dp(20)))
        self.add_widget(self.hex_in)

        # ---- buttons ----
        btns = BoxLayout(size_hint_y=None, height=dp(44), spacing=dp(6))
        self.btn_test = Button(text="发送测试")
        self.btn_chunk = Button(text="分块发送")
        self.btn_clear = Button(text="清空日志")
        btns.add_widget(self.btn_test)
        btns.add_widget(self.btn_chunk)
        btns.add_widget(self.btn_clear)
        self.add_widget(btns)

        self.btn_test.bind(on_release=lambda *_: self._run_test())
        self.btn_chunk.bind(on_release=lambda *_: self._run_chunk())
        self.btn_clear.bind(on_release=lambda *_: self._clear_log())

        # ---- result summary ----
        self.result_summary = Label(text="结果：len=0 md5=-", size_hint_y=None, height=dp(22))
        self.add_widget(self.result_summary)

        # ---- log ----
        self.log = LogView(size_hint=(1, 1))
        sv = ScrollView()
        sv.add_widget(self.log)
        self.add_widget(sv)

    def _clear_log(self):
        self.log.text = ""

    def _log(self, msg: str):
        def _append(_dt):
            self.log.text += msg + "\n"
            self.log.cursor = (0, len(self.log._lines))  # 尝试滚到底
        Clock.schedule_once(_append, 0)

    def _read_cfg(self):
        ph = self.proxy_host.text.strip()
        if not ph:
            raise ValueError("代理Host不能为空")
        pp = int(self.proxy_port.text.strip())
        th = self.target_host.text.strip()
        tp = int(self.target_port.text.strip())
        user = self.proxy_user.text.strip() or None
        pwd = self.proxy_pass.text.strip() or None
        return SocksConfig(proxy_host=ph, proxy_port=pp, username=user, password=pwd), TargetConfig(host=th, port=tp)

    def _read_payload(self) -> bytes:
        return parse_hex_string(self.hex_in.text)

    def _set_busy(self, busy: bool):
        self.btn_test.disabled = busy
        self.btn_chunk.disabled = busy

    def _run_test(self):
        def worker():
            try:
                Clock.schedule_once(lambda _dt: self._set_busy(True), 0)
                cfg, tgt = self._read_cfg()
                payload = self._read_payload()
                resp = self.tester.test_once(cfg, tgt, payload)
                summary = f"结果：len={len(resp) if resp else 0} md5={md5_hex(resp) if resp else '-'}"
                if resp:
                    self._log("----- RESPONSE HEX (前256字节) -----")
                    self._log(to_hex(resp[:256]) + ("..." if len(resp) > 256 else ""))
                Clock.schedule_once(lambda _dt: setattr(self.result_summary, "text", summary), 0)
            except Exception as e:
                self._log(f"[!] 错误: {e}")
            finally:
                Clock.schedule_once(lambda _dt: self._set_busy(False), 0)

        threading.Thread(target=worker, daemon=True).start()

    def _run_chunk(self):
        def worker():
            try:
                Clock.schedule_once(lambda _dt: self._set_busy(True), 0)
                cfg, tgt = self._read_cfg()
                payload = self._read_payload()
                cs = int(self.chunk_size.text.strip())
                interval = float(self.interval.text.strip())
                chunks = chunk_bytes(payload, cs)

                def prog(cur, total, all_resp):
                    Clock.schedule_once(lambda _dt: setattr(self.result_summary, "text",
                                                           f"进度：{cur}/{total} len={len(all_resp)}"), 0)

                all_resp = self.tester.test_chunked(cfg, tgt, chunks, interval_sec=interval, progress_cb=prog)
                summary = f"结果：len={len(all_resp) if all_resp else 0} md5={md5_hex(all_resp) if all_resp else '-'}"
                Clock.schedule_once(lambda _dt: setattr(self.result_summary, "text", summary), 0)
            except Exception as e:
                self._log(f"[!] 错误: {e}")
            finally:
                Clock.schedule_once(lambda _dt: self._set_busy(False), 0)

        threading.Thread(target=worker, daemon=True).start()


class SocksToolApp(App):
    def build(self):
        self.title = "SOCKS5 Tester"
        return Root()


if __name__ == "__main__":
    SocksToolApp().run()
