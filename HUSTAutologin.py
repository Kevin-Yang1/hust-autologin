#!/usr/bin/env python3

"""
HUST 校园网自动登录入口。

日常手动运行:
    python HUSTAutologin.py --once

脚本会在缺少账号或密码时交互式询问，并自动发现当前 portal 登录页、
登录接口地址、queryString 和 RSA 公钥，不再需要手动维护 LOGIN_URL 或
PASSWORD_HASH。
"""

from __future__ import annotations

import sys
from pathlib import Path

# ================== 配置方式 ==================
# 依赖:
#   python -m pip install requests
#
# 方式 1: 手动运行，按提示输入账号密码。适合临时使用。
#   python HUSTAutologin.py --once
#
# 方式 2: 用环境变量配置。适合开机自启、任务计划程序、systemd。
#   PowerShell 临时配置:
#     $env:CAMPUS_USER_ID="你的学号"
#     $env:CAMPUS_PASSWORD="你的校园网密码"
#     python HUSTAutologin.py --once --no-prompt
#
#   Linux/macOS 临时配置:
#     CAMPUS_USER_ID="你的学号" CAMPUS_PASSWORD="你的校园网密码" \
#       python HUSTAutologin.py --once --no-prompt
#
# 方式 3: 用命令行参数配置。适合快速测试；密码可能留在命令历史里。
#   python HUSTAutologin.py --once --user-id 你的学号 --password 你的密码
#
# 常用可选配置:
#   --loop --interval 30
#       守护模式，每 30 秒检测一次，掉线后自动登录。
#   --startup-delay 20
#       开机自启时先等 20 秒，避免网络还没就绪。
#   --verbose
#       输出更详细日志，排查 portal 探测、pageInfo、公钥解析等问题。
#   --force
#       当前检测为在线时也强制走一次登录流程。
#   --portal-entry-url "http://.../eportal/index.jsp?..."
#       自动发现 portal 失败时，临时指定当前浏览器里看到的完整登录页 URL。
#   --password-mode plain
#       默认模式；如果 portal 变更导致失败，可试 reverse-password-mac。
#
# 对应环境变量:
#   CAMPUS_USER_ID             校园网账号
#   CAMPUS_PASSWORD            校园网明文密码
#   CAMPUS_SERVICE             portal service 字段，通常留空
#   CAMPUS_DISCOVERY_URLS      portal 探测地址，多个地址用英文逗号或分号分隔
#   CAMPUS_PORTAL_ENTRY_URL    已知 portal 登录页完整 URL
#   CAMPUS_QUERY_STRING        已知 queryString，支持原始串或已编码串
#   CAMPUS_LOGIN_URL           显式指定登录接口；默认按 portal 域名推导
#   CAMPUS_PASSWORD_MODE       plain / password-mac / reverse-password-mac
#   CAMPUS_LOG_DIR             日志目录，默认 scripts/hust_autologin/logs
#
# 正常情况下不需要再配置 LOGIN_URL 或 PASSWORD_HASH。
# 脚本会自动探测登录页，调用 pageInfo 获取公钥，并从明文密码生成加密 password。
#
# 一键配置开机/登录自启:
#   Windows:
#     powershell -ExecutionPolicy Bypass -File .\setup\windows_autostart.ps1 -RunNow
#     默认创建开机启动任务；需要输入 Windows 账户密码，不是 PIN。
#     如只想登录后启动，可加 -AtLogOn。
#   Linux:
#     bash setup/linux_autostart.sh --run-now

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from hust_autologin import main


if __name__ == "__main__":
    raise SystemExit(main())
