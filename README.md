# HUST Autologin

HUST 校园网自动登录脚本。目标是只提供校园网账号和明文密码，脚本自动完成：

- 探测当前 portal 登录页地址
- 提取当前机器对应的 `queryString`
- 调用 `InterFace.do?method=pageInfo` 获取 RSA 公钥
- 生成登录请求里的加密 `password`
- 调用 `InterFace.do?method=login` 登录

## 文件说明

- `HUSTAutologin.py`: 日常入口，Windows / Linux 都可用。
- `HUSTAutologin_linux.py`: 兼容旧入口，内部调用同一份核心逻辑。
- `src/hust_autologin/core.py`: 实际实现，包含 portal 探测、`pageInfo`、RSA 加密和守护循环。
- `setup/windows_autostart.cmd`: Windows 双击配置入口。
- `setup/windows_autostart.ps1`: Windows 任务计划程序一键配置脚本。
- `setup/linux_autostart.sh`: Linux systemd user service 一键配置脚本。
- `logs/`: 运行日志目录，已在仓库忽略规则中排除。

## 依赖

```bash
python -m pip install -e .
```

脚本不会删除文件，不会覆盖原始数据；会联网访问校园网 portal 和外网连通性测试地址，会在 `logs/hust_autologin.log` 写运行日志。

## 最简单运行

手动运行一次，按提示输入账号密码：

```bash
python HUSTAutologin.py --once
```

守护模式：

```bash
python HUSTAutologin.py --loop --interval 30 --startup-delay 20
```

如果要用于开机自启，建议用环境变量，避免任务计划程序卡在交互输入：

PowerShell 临时设置：

```powershell
$env:CAMPUS_USER_ID="你的学号"
$env:CAMPUS_PASSWORD="你的校园网密码"
python HUSTAutologin.py --once --no-prompt
```

也可以直接传参：

```bash
python HUSTAutologin.py --once --user-id 你的学号 --password 你的密码
```

命令行密码可能出现在 shell 历史或进程列表里，长期使用更推荐环境变量。

## 一键自启动

Windows PowerShell：

最简单方式：双击运行 `setup/windows_autostart.cmd`。它会请求管理员权限，并打开一个 PowerShell 窗口继续配置。

也可以手动运行：

```powershell
cd <path-to-hust-autologin>
powershell -ExecutionPolicy Bypass -File .\setup\windows_autostart.ps1 -RunNow
```

脚本会创建任务计划程序 `HUSTAutologin`，触发器是“开机时”。它会询问两次密码：

- 校园网密码：用于登录校园网，以当前 Windows 用户可解密的 DPAPI SecureString 存到 `%APPDATA%\HUSTAutologin`。
- Windows 账户密码：用于让任务计划程序在用户未登录时运行；这里要输入账户密码，不是 PIN / Windows Hello。

如果只想登录后启动，可以加 `-AtLogOn`：

```powershell
powershell -ExecutionPolicy Bypass -File .\setup\windows_autostart.ps1 -RunNow -AtLogOn
```

Linux systemd 用户服务：

```bash
cd /path/to/hust-autologin
bash setup/linux_autostart.sh --run-now
```

脚本会创建 `~/.config/systemd/user/hust-autologin.service`，账号密码写到 `~/.config/hust-autologin/env`，权限为 `600`。

注意：这个脚本创建的是 systemd user service。默认情况下，它会在该 Linux 用户登录后自动运行；如果希望机器开机后、用户还没登录也运行，需要额外启用 linger：

```bash
sudo loginctl enable-linger "$USER"
```

检查是否已启用：

```bash
loginctl show-user "$USER" -p Linger
```

输出 `Linger=yes` 时，user service 才会在未登录时也随系统启动。查看运行状态和日志：

```bash
systemctl --user status hust-autologin.service
journalctl --user -u hust-autologin.service -f
```

如果想做成真正的系统级开机服务，不依赖 linger，需要改用 `/etc/systemd/system/hust-autologin.service` 并把配置放到系统级路径，例如 `/etc/hust-autologin/env`；这会需要 `sudo`，安全边界也和用户服务不同。

## 可选配置

- `CAMPUS_USER_ID`: 校园网账号。
- `CAMPUS_PASSWORD`: 校园网明文密码。
- `CAMPUS_SERVICE`: portal `service` 字段，默认空。
- `CAMPUS_DISCOVERY_URLS`: 自动发现 portal 的 HTTP 地址，多个地址用英文逗号或分号分隔；默认优先试 `http://123.123.123.123/`。
- `CAMPUS_PORTAL_ENTRY_URL`: 已知的 portal 登录页完整 URL。
- `CAMPUS_QUERY_STRING`: 已知的 queryString，支持原始串或已编码串。
- `CAMPUS_PORTAL_INDEX_URL`: 手头只有 `CAMPUS_QUERY_STRING` 时可提供 portal index 地址。
- `CAMPUS_LOGIN_URL`: 显式指定登录接口；默认按 portal 域名推导。
- `CAMPUS_CONNECTIVITY_TEST_URL`: 在线检测地址，默认 `http://www.baidu.com`。
- `CAMPUS_PASSWORD_MODE`: RSA 加密前的密码预处理方式，默认 `plain`。
- `CAMPUS_LOG_DIR`: 日志目录，默认项目目录下的 `logs/`。

`CAMPUS_PASSWORD_MODE` 可选：

- `plain`: 当前华科网页认证常见流程，直接加密明文密码。
- `password-mac`: 先拼成 `密码>mac` 再加密。
- `reverse-password-mac`: 先拼成 `密码>mac`，反转后再加密。

如果默认模式登录失败，而日志里能正常拿到 `pageInfo` 公钥，可以尝试：

```bash
python HUSTAutologin.py --once --password-mode reverse-password-mac --verbose
```

## systemd 示例

环境文件，例如 `/opt/hust-autologin/.env`：

```bash
CAMPUS_USER_ID=你的学号
CAMPUS_PASSWORD=你的校园网密码
```

用户级服务：

```ini
[Unit]
Description=HUST campus autologin
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/hust-autologin
EnvironmentFile=/opt/hust-autologin/.env
ExecStart=/usr/bin/python3 /opt/hust-autologin/HUSTAutologin.py --loop --interval 30 --startup-delay 20 --no-prompt
Restart=always
RestartSec=10

[Install]
WantedBy=default.target
```

## 常见失败原因

- 当前已经在线，portal 不再返回登录页；断开校园网认证后再试，或显式提供 `--portal-entry-url`。
- `requests` 未安装。
- 系统代理拦截了请求；脚本默认不使用系统代理。
- portal 页面结构变化，导致找不到 `queryString` 或 `pageInfo` 公钥。
- 密码预处理模式变化，可试 `--password-mode reverse-password-mac`。

排障时建议加 `--verbose`，日志会记录探测 URL、响应链、`pageInfo` 字段和登录接口返回摘要。
