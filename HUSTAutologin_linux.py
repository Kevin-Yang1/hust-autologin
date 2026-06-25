#!/usr/bin/env python3

"""
兼容入口。

原 Linux 服务器版的完整实现已移动到 `hust_autologin/core.py`，这个文件保留
原有文件名，方便旧的 systemd 配置和命令继续运行。
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from hust_autologin import main


if __name__ == "__main__":
    raise SystemExit(main())
