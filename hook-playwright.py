from PyInstaller.utils.hooks import collect_all

datas, binaries, hiddenimports = collect_all('playwright')
binaries = []  # bỏ binaries để PyInstaller không xử lý Chromium.app