import socket
import hashlib
import base64
import json
import ssl
import threading
from urllib.parse import urlparse

import requests
from kivy.app import App
from kivy.clock import Clock
from kivy.core.clipboard import Clipboard
from kivy.metrics import dp
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.gridlayout import GridLayout
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button
from kivy.uix.spinner import Spinner
from kivy.uix.scrollview import ScrollView
from kivy.utils import platform


class DeepHatApp(App):
    title = "DeepHat Toolkit"

    def build(self):
        root = BoxLayout(orientation="vertical", padding=dp(12), spacing=dp(8))
        title = Label(text="[b]DeepHat Toolkit[/b]", markup=True, size_hint_y=None,
                      height=dp(42), font_size="22sp")
        root.add_widget(title)

        note = Label(text="Use network tools only on systems you own or have permission to test.",
                     size_hint_y=None, height=dp(38), font_size="12sp")
        root.add_widget(note)

        self.tool = Spinner(
            text="Hash",
            values=("Hash", "Base64", "DNS Lookup", "TCP Port Scan",
                    "HTTP Headers", "SSL Certificate", "JSON Formatter", "Dockerfile Generator"),
            size_hint_y=None, height=dp(48)
        )
        root.add_widget(self.tool)

        self.input_label = Label(text="Text to hash", size_hint_y=None, height=dp(28),
                                 halign="left", valign="middle")
        self.input_label.bind(size=lambda inst, val: setattr(inst, "text_size", val))
        root.add_widget(self.input_label)

        self.input = TextInput(hint_text="Enter text, hostname, URL, JSON, etc.",
                               multiline=True, size_hint_y=None, height=dp(105))
        root.add_widget(self.input)

        row = BoxLayout(size_hint_y=None, height=dp(44), spacing=dp(6))
        self.action = Spinner(text="encode", values=("encode", "decode"),
                              size_hint_x=0.42)
        row.add_widget(self.action)
        self.start_port = TextInput(text="1", hint_text="Start port", multiline=False,
                                    input_filter="int", size_hint_x=0.29)
        self.end_port = TextInput(text="1024", hint_text="End port", multiline=False,
                                  input_filter="int", size_hint_x=0.29)
        row.add_widget(self.start_port)
        row.add_widget(self.end_port)
        root.add_widget(row)

        buttons = GridLayout(cols=2, spacing=dp(8), size_hint_y=None, height=dp(94))
        run_btn = Button(text="Run", size_hint_y=None, height=dp(42))
        run_btn.bind(on_release=self.run_tool)
        buttons.add_widget(run_btn)
        copy_btn = Button(text="Copy result", size_hint_y=None, height=dp(42))
        copy_btn.bind(on_release=self.copy_result)
        buttons.add_widget(copy_btn)
        root.add_widget(buttons)

        scroll = ScrollView()
        self.output = TextInput(text="Choose a tool, enter the required input, then tap Run.",
                                readonly=True, multiline=True, size_hint_y=None,
                                height=dp(500), font_size="13sp")
        self.output.bind(minimum_height=self.output.setter("height"))
        scroll.add_widget(self.output)
        root.add_widget(scroll)

        self.tool.bind(text=self.update_labels)
        self.update_labels()
        return root

    def update_labels(self, *_):
        labels = {
            "Hash": "Text to hash",
            "Base64": "Text to encode/decode",
            "DNS Lookup": "Hostname (e.g. example.com)",
            "TCP Port Scan": "Hostname/IP you own or are authorized to test",
            "HTTP Headers": "Full URL (e.g. https://example.com)",
            "SSL Certificate": "Hostname (e.g. example.com)",
            "JSON Formatter": "JSON text",
            "Dockerfile Generator": "Optional app name (default: myapp)"
        }
        self.input_label.text = labels.get(self.tool.text, "Input")
        self.action.disabled = self.tool.text != "Base64"
        self.start_port.disabled = self.tool.text != "TCP Port Scan"
        self.end_port.disabled = self.tool.text != "TCP Port Scan"

    def set_output(self, text):
        self.output.text = str(text)

    def run_tool(self, *_):
        selected = self.tool.text
        data = self.input.text.strip()
        self.set_output("Working…")
        threading.Thread(target=self._run_worker, args=(selected, data), daemon=True).start()

    def _run_worker(self, selected, data):
        try:
            if selected == "Hash":
                raw = data.encode("utf-8")
                result = (f"MD5:    {hashlib.md5(raw).hexdigest()}\n"
                          f"SHA1:   {hashlib.sha1(raw).hexdigest()}\n"
                          f"SHA256: {hashlib.sha256(raw).hexdigest()}")
            elif selected == "Base64":
                if self.action.text == "decode":
                    result = base64.b64decode(data, validate=True).decode("utf-8", errors="replace")
                else:
                    result = base64.b64encode(data.encode("utf-8")).decode("utf-8")
            elif selected == "DNS Lookup":
                ip = socket.gethostbyname(data)
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except Exception:
                    hostname = "(reverse lookup unavailable)"
                result = f"IP: {ip}\nHostname: {hostname}"
            elif selected == "TCP Port Scan":
                host = data
                start = int(self.start_port.text or "1")
                end = int(self.end_port.text or "1024")
                if not (1 <= start <= end <= 65535):
                    raise ValueError("Ports must be between 1 and 65535, with start <= end.")
                if end - start > 2047:
                    raise ValueError("For mobile safety, scan at most 2048 ports at a time.")
                found = []
                for port in range(start, end + 1):
                    try:
                        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                            s.settimeout(0.5)
                            if s.connect_ex((host, port)) == 0:
                                found.append(port)
                    except OSError:
                        pass
                result = "Open ports:\n" + ("\n".join(map(str, found)) if found else "None found")
                result += f"\n\nTotal open ports: {len(found)}"
            elif selected == "HTTP Headers":
                url = data
                if not urlparse(url).scheme:
                    url = "https://" + url
                r = requests.get(url, timeout=8, allow_redirects=True,
                                 headers={"User-Agent": "DeepHatToolkit/1.0"})
                result = f"Status: {r.status_code}\nFinal URL: {r.url}\n"
                result += "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            elif selected == "SSL Certificate":
                host = data
                port = 443
                context = ssl.create_default_context()
                with socket.create_connection((host, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=host) as ssock:
                        cert = ssock.getpeercert()
                        result = (f"Subject: {dict(x[0] for x in cert.get('subject', []))}\n"
                                  f"Issuer: {dict(x[0] for x in cert.get('issuer', []))}\n"
                                  f"Expires: {cert.get('notAfter', 'Unknown')}\n"
                                  f"Protocol: {ssock.version()}")
            elif selected == "JSON Formatter":
                result = json.dumps(json.loads(data), indent=2, ensure_ascii=False)
            elif selected == "Dockerfile Generator":
                name = data or "myapp"
                safe_name = "".join(c for c in name if c.isalnum() or c in "-_") or "myapp"
                result = (f"# Dockerfile for {safe_name}\nFROM python:3.11-slim\n"
                          f"WORKDIR /app\nCOPY . .\nRUN pip install --no-cache-dir requests\n"
                          f'CMD ["python", "app.py"]')
            else:
                result = "Please choose a tool."
        except Exception as exc:
            result = f"Error: {exc}"
        Clock.schedule_once(lambda dt, value=result: self.set_output(value), 0)

    def copy_result(self, *_):
        try:
            Clipboard.copy(self.output.text)
            self.set_output(self.output.text + "\n\n[Copied to clipboard]")
        except Exception as exc:
            self.set_output(self.output.text + f"\n\nCopy error: {exc}")


if __name__ == "__main__":
    DeepHatApp().run()
