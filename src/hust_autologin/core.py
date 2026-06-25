#!/usr/bin/env python3

"""
HUST campus network autologin core.

The script discovers the current eportal entry page at runtime, reads the
public RSA parameters exposed by that page, and builds the encrypted password
from the plain campus network password. That removes the need to keep a stale
LOGIN_URL, queryString, or captured PASSWORD_HASH in the local script.
"""

from __future__ import annotations

import getpass
import html
import io
import json
import logging
import os
import random
import re
import sys
import time
from argparse import ArgumentParser, Namespace
from dataclasses import dataclass, replace
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote, unquote, urljoin, urlparse

try:
    import requests
    import urllib3
except ModuleNotFoundError:
    requests = None  # type: ignore[assignment]
    urllib3 = None  # type: ignore[assignment]


try:
    if hasattr(sys.stdout, "buffer"):
        sys.stdout = io.TextIOWrapper(
            sys.stdout.buffer,
            encoding="utf-8",
            errors="replace",
        )
    if hasattr(sys.stderr, "buffer"):
        sys.stderr = io.TextIOWrapper(
            sys.stderr.buffer,
            encoding="utf-8",
            errors="replace",
        )
except Exception:  # noqa: BLE001
    pass

if urllib3 is not None:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


@dataclass
class Config:
    user_id: str
    password: str
    service: str
    portal_entry_url: str | None
    portal_index_url: str | None
    login_url: str | None
    query_string: str | None
    discovery_urls: list[str]
    password_mode: str
    connectivity_test_url: str
    connectivity_timeout: int
    max_login_retries: int
    base_retry_delay: int
    retry_jitter: float
    default_interval: int
    log_dir: Path


@dataclass
class PortalContext:
    entry_url: str
    login_url: str
    query_string: str
    mac: str
    password_encrypt: str
    public_key_exponent: str
    public_key_modulus: str


MAX_LOG_BYTES = 512 * 1024
BACKUP_COUNT = 3

logger = logging.getLogger("hust_autologin")
logger.setLevel(logging.INFO)
_formatter = logging.Formatter(
    fmt="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger.addHandler(logging.NullHandler())


PORTAL_KEYWORDS = [
    "eportal",
    "wlanuserip",
    "portaluserv2",
    "drcom",
    "srun_portal",
]

PORTAL_QUERY_KEYS = [
    "wlanuserip",
    "wlanacip",
    "wlanacname",
    "mac",
    "ssid",
    "nasip",
]

PASSWORD_MODES = [
    "plain",
    "password-mac",
    "reverse-password-mac",
]

DEFAULT_DISCOVERY_URLS = [
    "http://123.123.123.123/",
    "http://1.1.1.1",
    "http://www.msftconnecttest.com/redirect",
]


def normalize_query_string(value: str | None) -> str | None:
    if not value:
        return None

    candidates = [value]
    decoded = value
    for _ in range(2):
        next_decoded = unquote(decoded)
        if next_decoded == decoded:
            break
        candidates.append(next_decoded)
        decoded = next_decoded

    for candidate in candidates:
        if "=" in candidate or "&" in candidate:
            return candidate
    return value


def _read_int_env(name: str, default: int) -> int:
    raw_value = os.getenv(name, "").strip()
    if not raw_value:
        return default
    try:
        return int(raw_value)
    except ValueError:
        raise SystemExit(f"{name} 必须是整数，当前值: {raw_value!r}") from None


def _read_float_env(name: str, default: float) -> float:
    raw_value = os.getenv(name, "").strip()
    if not raw_value:
        return default
    try:
        return float(raw_value)
    except ValueError:
        raise SystemExit(f"{name} 必须是数字，当前值: {raw_value!r}") from None


def _read_url_list_env(name: str) -> list[str]:
    raw_value = os.getenv(name, "").strip()
    if not raw_value:
        return []
    return [item.strip() for item in re.split(r"[;,]", raw_value) if item.strip()]


def load_config_from_env() -> Config:
    connectivity_test_url = os.getenv(
        "CAMPUS_CONNECTIVITY_TEST_URL",
        "http://www.baidu.com",
    ).strip()
    discovery_urls = _read_url_list_env("CAMPUS_DISCOVERY_URLS")
    if not discovery_urls:
        discovery_urls = [*DEFAULT_DISCOVERY_URLS, connectivity_test_url]

    password_mode = os.getenv("CAMPUS_PASSWORD_MODE", "plain").strip() or "plain"
    if password_mode not in PASSWORD_MODES:
        raise SystemExit(
            "CAMPUS_PASSWORD_MODE 必须是 "
            + ", ".join(PASSWORD_MODES)
            + f" 之一，当前值: {password_mode!r}"
        )

    tool_dir = Path(__file__).resolve().parents[2]
    log_dir = Path(
        os.getenv(
            "CAMPUS_LOG_DIR",
            str(tool_dir / "logs"),
        )
    ).expanduser()
    return Config(
        user_id=os.getenv("CAMPUS_USER_ID", "").strip(),
        password=os.getenv("CAMPUS_PASSWORD", "").strip(),
        service=os.getenv("CAMPUS_SERVICE", "").strip(),
        portal_entry_url=os.getenv("CAMPUS_PORTAL_ENTRY_URL", "").strip() or None,
        portal_index_url=os.getenv("CAMPUS_PORTAL_INDEX_URL", "").strip() or None,
        login_url=os.getenv("CAMPUS_LOGIN_URL", "").strip() or None,
        query_string=normalize_query_string(os.getenv("CAMPUS_QUERY_STRING", "").strip()),
        discovery_urls=discovery_urls,
        password_mode=password_mode,
        connectivity_test_url=connectivity_test_url,
        connectivity_timeout=_read_int_env("CAMPUS_CONNECTIVITY_TIMEOUT", 4),
        max_login_retries=_read_int_env("CAMPUS_MAX_LOGIN_RETRIES", 5),
        base_retry_delay=_read_int_env("CAMPUS_BASE_RETRY_DELAY", 2),
        retry_jitter=_read_float_env("CAMPUS_RETRY_JITTER", 0.4),
        default_interval=_read_int_env("CAMPUS_DEFAULT_INTERVAL", 30),
        log_dir=log_dir,
    )


CONFIG = load_config_from_env()


def require_requests() -> None:
    if requests is None:
        raise SystemExit(
            "缺少依赖 requests。请先安装: python -m pip install requests"
        )


def setup_logging(log_dir: Path) -> Path:
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "hust_autologin.log"
    logger.handlers.clear()
    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=MAX_LOG_BYTES,
        backupCount=BACKUP_COUNT,
        encoding="utf-8",
    )
    file_handler.setFormatter(_formatter)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(_formatter)
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    return log_file


def parse_args() -> Namespace:
    parser = ArgumentParser(description="HUST 校园网自动登录脚本")
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument("--once", action="store_true", help="只执行一次检测/登录后退出")
    mode_group.add_argument("--loop", action="store_true", help="持续守护模式（默认）")
    parser.add_argument(
        "--interval",
        type=int,
        default=CONFIG.default_interval,
        help=f"守护模式检测间隔秒数（默认 {CONFIG.default_interval}）",
    )
    parser.add_argument("--verbose", action="store_true", help="启用 DEBUG 日志输出")
    parser.add_argument(
        "--startup-delay",
        type=int,
        default=0,
        help="启动后先延迟 N 秒，再开始检测或登录",
    )
    parser.add_argument(
        "--user-id",
        default=CONFIG.user_id,
        help="校园网账号；默认读取 CAMPUS_USER_ID，未提供时交互输入",
    )
    parser.add_argument(
        "--password",
        default=CONFIG.password,
        help="校园网明文密码；默认读取 CAMPUS_PASSWORD，未提供时安全输入",
    )
    parser.add_argument(
        "--no-prompt",
        action="store_true",
        help="缺少账号或密码时直接报错，适合计划任务/systemd",
    )
    parser.add_argument(
        "--service",
        default=CONFIG.service,
        help="portal service 字段；默认读取 CAMPUS_SERVICE 或留空",
    )
    parser.add_argument(
        "--portal-entry-url",
        default=CONFIG.portal_entry_url,
        help="显式指定 portal 登录页完整 URL；未指定时自动发现",
    )
    parser.add_argument(
        "--connectivity-test-url",
        default=CONFIG.connectivity_test_url,
        help=f"用于触发 portal 跳转的外网 HTTP URL（默认 {CONFIG.connectivity_test_url}）",
    )
    parser.add_argument(
        "--discovery-url",
        action="append",
        dest="discovery_urls",
        help="用于自动发现 portal 的 HTTP 地址；可重复传入，默认先试 123.123.123.123",
    )
    parser.add_argument(
        "--password-mode",
        choices=PASSWORD_MODES,
        default=CONFIG.password_mode,
        help="密码 RSA 加密前的预处理方式；华科当前网页认证通常使用 plain",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="即使检测到当前已在线，也强制执行一次登录流程",
    )
    return parser.parse_args()


def _stdin_is_interactive() -> bool:
    try:
        return sys.stdin.isatty()
    except Exception:  # noqa: BLE001
        return False


def resolve_config(args: Namespace) -> Config:
    config = replace(
        load_config_from_env(),
        user_id=(args.user_id or "").strip(),
        password=args.password or "",
        service=(args.service or "").strip(),
        portal_entry_url=args.portal_entry_url or None,
        discovery_urls=args.discovery_urls or load_config_from_env().discovery_urls,
        password_mode=args.password_mode,
        connectivity_test_url=(args.connectivity_test_url or "").strip(),
    )

    if not args.no_prompt and _stdin_is_interactive():
        if not config.user_id:
            config = replace(config, user_id=input("校园网账号: ").strip())
        if not config.password:
            try:
                password = getpass.getpass("校园网密码: ")
            except Exception:  # noqa: BLE001
                password = input("校园网密码: ")
            config = replace(config, password=password)

    missing: list[str] = []
    if not config.user_id:
        missing.append("账号（--user-id 或 CAMPUS_USER_ID）")
    if not config.password:
        missing.append("密码（--password 或 CAMPUS_PASSWORD）")
    if missing:
        raise SystemExit(
            "缺少" + "、".join(missing) + "。手动运行可省略参数并按提示输入。"
        )
    return config


def create_session() -> requests.Session:
    require_requests()
    session = requests.Session()
    session.trust_env = False
    session.headers.update(
        {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/126.0 Safari/537.36"
            )
        }
    )
    return session


def looks_like_portal_url(url: str) -> bool:
    lowered = url.lower()
    return "/eportal/" in lowered or "wlanuserip=" in lowered


def looks_like_portal_entry_url(url: str) -> bool:
    parsed = urlparse(url)
    if not parsed.query:
        return False
    path = parsed.path.lower()
    if not path.endswith("index.jsp"):
        return False
    lowered_query = parsed.query.lower()
    return any(f"{key}=" in lowered_query for key in PORTAL_QUERY_KEYS)


def response_looks_like_portal(response: requests.Response) -> bool:
    if looks_like_portal_url(response.url):
        return True
    location = response.headers.get("Location", "")
    if location and looks_like_portal_url(location):
        return True
    text = response.text.lower()
    return any(keyword in text for keyword in PORTAL_KEYWORDS)


def find_portal_entry_url_in_response(response: requests.Response) -> str | None:
    for history_response in reversed(response.history):
        if looks_like_portal_entry_url(history_response.url):
            return history_response.url
    if looks_like_portal_entry_url(response.url):
        return response.url

    text = html.unescape(response.text)
    absolute_pattern = re.compile(
        r"""https?://[^\s"'<>\\)]+/eportal/index\.jsp\?[^\s"'<>\\)]+""",
        re.IGNORECASE,
    )
    relative_pattern = re.compile(
        r"""(?:\./|\.\./|/)?(?:eportal/)?index\.jsp\?[^\s"'<>\\)]+""",
        re.IGNORECASE,
    )

    absolute_match = absolute_pattern.search(text)
    if absolute_match:
        return absolute_match.group(0)

    relative_match = relative_pattern.search(text)
    if relative_match:
        return urljoin(response.url, relative_match.group(0))

    return None


def find_query_string_in_text(text: str) -> str | None:
    text = html.unescape(text)
    patterns = [
        re.compile(r"""queryString\s*[:=]\s*["']([^"']+)["']""", re.IGNORECASE),
        re.compile(r"""index\.jsp\?([^\s"'<>\\)]+)""", re.IGNORECASE),
        re.compile(
            r"""((?:wlanuserip|wlanacip|wlanacname|mac|ssid|nasip)=[^\s"'<>\\)]+(?:&[A-Za-z0-9_]+=[^\s"'<>\\)]*)*)""",
            re.IGNORECASE,
        ),
    ]
    for pattern in patterns:
        match = pattern.search(text)
        if not match:
            continue
        candidate = normalize_query_string(match.group(1))
        if candidate and any(f"{key}=" in candidate.lower() for key in PORTAL_QUERY_KEYS):
            return candidate
    return None


def summarize_response_for_debug(response: requests.Response) -> str:
    compact_text = re.sub(r"\s+", " ", html.unescape(response.text)).strip()
    if len(compact_text) > 200:
        compact_text = compact_text[:200] + "..."
    return compact_text


def format_response_chain(response: requests.Response) -> str:
    urls = [history_response.url for history_response in response.history] + [response.url]
    return " -> ".join(urls)


def is_online(session: requests.Session, config: Config) -> bool:
    try:
        response = session.get(
            config.connectivity_test_url,
            timeout=config.connectivity_timeout,
            verify=False,
            allow_redirects=False,
        )
        if not (200 <= response.status_code < 400):
            return False
        if 300 <= response.status_code < 400:
            return not looks_like_portal_url(response.headers.get("Location", ""))
        return not response_looks_like_portal(response)
    except Exception:
        return False


def discover_entry_response(
    session: requests.Session,
    config: Config,
    portal_entry_url: str | None,
) -> requests.Response:
    if portal_entry_url:
        logger.debug("使用显式 portal 入口 URL: %s", portal_entry_url)
        return session.get(
            portal_entry_url,
            timeout=10,
            verify=False,
            allow_redirects=True,
        )

    if config.query_string:
        if config.portal_index_url:
            entry_url = f"{config.portal_index_url}?{config.query_string}"
            logger.debug("使用环境变量中的 queryString 构造 portal 入口 URL: %s", entry_url)
            return session.get(
                entry_url,
                timeout=10,
                verify=False,
                allow_redirects=True,
            )
        logger.debug("已提供 queryString，但未提供固定 portal 地址；先自动探测当前 portal host")

    last_response: requests.Response | None = None
    for discovery_url in config.discovery_urls:
        logger.debug("尝试通过 %s 自动发现 portal 登录页", discovery_url)
        try:
            response = session.get(
                discovery_url,
                timeout=10,
                verify=False,
                allow_redirects=True,
            )
        except Exception as exc:  # noqa: BLE001
            logger.debug("探测 %s 失败: %s", discovery_url, exc)
            continue

        last_response = response
        logger.debug("探测响应: HTTP %s -> %s", response.status_code, response.url)
        derived_entry_url = find_portal_entry_url_in_response(response)
        if derived_entry_url and derived_entry_url != response.url:
            logger.debug("从中间跳转页解析出 portal 登录页 URL: %s", derived_entry_url)
            return session.get(
                derived_entry_url,
                timeout=10,
                verify=False,
                allow_redirects=True,
            )
        if response_looks_like_portal(response):
            return response

    if last_response is not None:
        return last_response
    raise RuntimeError("自动发现 portal 登录页失败，所有探测 URL 均无法访问")


def extract_field_value(html_text: str, field_name: str) -> str:
    input_pattern = re.compile(r"<input\b[^>]*>", re.IGNORECASE)
    field_pattern = re.compile(
        r'\b(?:id|name)\s*=\s*["\']' + re.escape(field_name) + r'["\']',
        re.IGNORECASE,
    )
    value_pattern = re.compile(r'\bvalue\s*=\s*["\']([^"\']*)["\']', re.IGNORECASE)
    for match in input_pattern.finditer(html_text):
        tag = match.group(0)
        if not field_pattern.search(tag):
            continue
        value_match = value_pattern.search(tag)
        if value_match:
            return html.unescape(value_match.group(1))

    assignment_patterns = [
        re.compile(
            re.escape(field_name) + r"""\s*[:=]\s*["']([^"']+)["']""",
            re.IGNORECASE,
        ),
        re.compile(
            r"""["']""" + re.escape(field_name) + r"""["']\s*:\s*["']([^"']+)["']""",
            re.IGNORECASE,
        ),
    ]
    for pattern in assignment_patterns:
        match = pattern.search(html_text)
        if match:
            return html.unescape(match.group(1))
    return ""


def derive_interface_url(entry_url: str, method: str) -> str:
    parsed = urlparse(entry_url)
    return f"{parsed.scheme}://{parsed.netloc}/eportal/InterFace.do?method={method}"


def derive_login_url(entry_url: str, explicit_login_url: str | None) -> str:
    if explicit_login_url:
        return explicit_login_url
    return derive_interface_url(entry_url, "login")


def build_portal_headers(entry_url: str) -> dict[str, str]:
    parsed = urlparse(entry_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    return {
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "Origin": origin,
        "Referer": entry_url,
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
        ),
    }


def normalize_password_encrypt(value: Any) -> str:
    return "true" if str(value).lower() == "true" else "false"


def fetch_page_info(
    session: requests.Session,
    entry_url: str,
    query_string: str,
) -> dict[str, Any]:
    page_info_url = derive_interface_url(entry_url, "pageInfo")
    response = session.post(
        page_info_url,
        headers=build_portal_headers(entry_url),
        data={"queryString": prequote_form_value(query_string)},
        timeout=10,
        verify=False,
    )
    logger.debug("pageInfo HTTP %s -> %s", response.status_code, page_info_url)
    response.raise_for_status()
    parsed = response.json()
    if not isinstance(parsed, dict):
        raise RuntimeError("pageInfo 返回不是 JSON object")
    logger.debug("pageInfo 返回字段: %s", ", ".join(sorted(parsed.keys())))
    return parsed


def fetch_portal_context(
    session: requests.Session,
    config: Config,
    portal_entry_url: str | None,
) -> PortalContext:
    response = discover_entry_response(session, config, portal_entry_url)
    if not response_looks_like_portal(response):
        raise RuntimeError(
            "未能定位到 portal 登录页。请确保当前网络会重定向到认证页，"
            "或显式提供 --portal-entry-url"
        )

    entry_url = response.url
    raw_query = (
        normalize_query_string(urlparse(entry_url).query)
        or find_query_string_in_text(response.text)
        or config.query_string
    )
    if not raw_query:
        logger.debug("当前响应链: %s", format_response_chain(response))
        logger.debug("当前响应 URL: %s", response.url)
        derived_entry_url = find_portal_entry_url_in_response(response)
        if derived_entry_url:
            logger.debug("页面源码中发现的 portal 登录页线索: %s", derived_entry_url)
        logger.debug("页面内容摘要: %s", summarize_response_for_debug(response))
        raise RuntimeError("无法从 portal 登录页 URL 中提取 queryString")

    page_info: dict[str, Any] = {}
    try:
        page_info = fetch_page_info(session, entry_url, raw_query)
    except Exception as exc:  # noqa: BLE001
        logger.debug("pageInfo 获取失败，改用登录页 HTML 兜底解析: %s", exc)

    mac = (
        extract_field_value(response.text, "macString")
        or extract_field_value(response.text, "mac")
        or parse_qs(raw_query).get("mac", [""])[0]
        or "111111111"
    )
    password_encrypt = normalize_password_encrypt(
        page_info.get("passwordEncrypt")
        if "passwordEncrypt" in page_info
        else (extract_field_value(response.text, "passwordEncrypt") or "true")
    )
    public_key_exponent = str(
        page_info.get("publicKeyExponent") or extract_field_value(response.text, "publicKeyExponent")
    )
    public_key_modulus = str(
        page_info.get("publicKeyModulus") or extract_field_value(response.text, "publicKeyModulus")
    )

    if password_encrypt == "true" and (not public_key_exponent or not public_key_modulus):
        raise RuntimeError("无法从 portal 登录页解析 RSA 公钥，请检查页面结构或 portal 入口 URL")

    return PortalContext(
        entry_url=entry_url,
        login_url=derive_login_url(entry_url, config.login_url),
        query_string=raw_query,
        mac=mac,
        password_encrypt=password_encrypt,
        public_key_exponent=public_key_exponent,
        public_key_modulus=public_key_modulus,
    )


def prequote_form_value(value: str) -> str:
    return quote(value, safe="")


def rsa_no_padding_hex(text: str, exponent_hex: str, modulus_hex: str) -> str:
    exponent = int(exponent_hex, 16)
    modulus = int(modulus_hex, 16)
    input_number = int.from_bytes(text.encode("utf-8"), byteorder="big")
    crypt_number = pow(input_number, exponent, modulus)
    length = max(1, (modulus.bit_length() + 7) // 8)
    return crypt_number.to_bytes(length, byteorder="big").hex()


def prepare_password_for_mode(
    plain_password: str,
    context: PortalContext,
    password_mode: str,
) -> str:
    if password_mode == "plain":
        return plain_password
    password_mac = f"{plain_password}>{context.mac or '111111111'}"
    if password_mode == "password-mac":
        return password_mac
    if password_mode == "reverse-password-mac":
        return password_mac[::-1]
    raise ValueError(f"未知 password_mode: {password_mode}")


def build_encrypted_password(
    plain_password: str,
    context: PortalContext,
    password_mode: str,
) -> str:
    if context.password_encrypt != "true":
        return plain_password
    prepared_password = prepare_password_for_mode(plain_password, context, password_mode)
    return rsa_no_padding_hex(
        prepared_password,
        context.public_key_exponent,
        context.public_key_modulus,
    )


def build_payload(config: Config, context: PortalContext) -> dict[str, str]:
    password = build_encrypted_password(config.password, context, config.password_mode)
    return {
        "userId": prequote_form_value(config.user_id),
        "password": prequote_form_value(password),
        "service": prequote_form_value(config.service),
        "queryString": prequote_form_value(context.query_string),
        "operatorPwd": "",
        "operatorUserId": "",
        "validcode": "",
        "passwordEncrypt": prequote_form_value(context.password_encrypt),
    }


def is_success_response(response: requests.Response) -> tuple[bool, dict[str, Any] | None]:
    text = response.text.strip()
    parsed: dict[str, Any] | None = None
    success = False

    if response.headers.get("Content-Type", "").lower().startswith("application/json") or text.startswith("{"):
        try:
            parsed = response.json()
            if isinstance(parsed, dict):
                status_value = (
                    parsed.get("result")
                    or parsed.get("success")
                    or parsed.get("status")
                    or parsed.get("ret_code")
                )
                success = str(status_value).lower() in {"0", "true", "success", "ok"}
        except Exception:  # noqa: BLE001
            parsed = None

    if not success and response.status_code == 200:
        keywords = [
            "成功",
            "online",
            "Login ok",
            "PortalUserV2",
            "success.jsp",
            "userIndex=",
            "keepaliveInterval=",
        ]
        success = any(keyword.lower() in text.lower() for keyword in keywords)

    return success, parsed


def login_once(
    session: requests.Session,
    config: Config,
    portal_entry_url: str | None,
) -> bool:
    context = fetch_portal_context(session, config, portal_entry_url)
    payload = build_payload(config, context)

    logger.info("开始发送登录请求 -> %s", context.login_url)
    logger.debug("使用的 portal 入口 URL: %s", context.entry_url)
    logger.debug("登录使用的 mac: %s", context.mac)
    logger.debug("密码预处理模式: %s", config.password_mode)

    response = session.post(
        url=context.login_url,
        headers=build_portal_headers(context.entry_url),
        data=payload,
        timeout=10,
        verify=False,
    )
    logger.info("HTTP 状态码: %s", response.status_code)
    logger.info("Content-Type: %s", response.headers.get("Content-Type", ""))

    success, parsed = is_success_response(response)
    if parsed is not None:
        logger.info("返回(JSON裁剪): %s", json.dumps(parsed, ensure_ascii=False)[:300])
    else:
        logger.info("返回(文本前 200 字): %s", response.text.strip()[:200])

    if success:
        logger.info("登录判定: 成功")
    else:
        logger.warning("登录判定: 失败")
    return success


def ensure_online_with_retry(
    session: requests.Session,
    config: Config,
    portal_entry_url: str | None,
) -> bool:
    for attempt in range(1, config.max_login_retries + 1):
        try:
            if login_once(session, config, portal_entry_url):
                return True
        except Exception as exc:  # noqa: BLE001
            logger.exception("第 %d 次登录请求异常: %s", attempt, exc)

        delay = config.base_retry_delay * (2 ** (attempt - 1))
        jitter = delay * config.retry_jitter * (random.random() * 2 - 1)
        sleep_seconds = max(1.0, delay + jitter)
        logger.info("第 %d 次登录失败，%.1f 秒后重试…", attempt, sleep_seconds)
        time.sleep(sleep_seconds)

    logger.error("所有 %d 次登录尝试均失败", config.max_login_retries)
    return False


def loop_guard(
    session: requests.Session,
    config: Config,
    interval: int,
    portal_entry_url: str | None,
) -> None:
    logger.info("进入守护循环，检测间隔 %d 秒。按 Ctrl+C 退出。", interval)
    last_login_success_time: float | None = None
    check_count = 0
    while True:
        try:
            check_count += 1
            if is_online(session, config):
                if check_count % 10 == 0:
                    logger.info(
                        "状态正常 (已检测 %d 次，运行时长约 %d 分钟)",
                        check_count,
                        check_count * interval // 60,
                    )
            else:
                logger.warning("检测到掉线，开始自动登录…")
                if ensure_online_with_retry(session, config, portal_entry_url):
                    last_login_success_time = time.time()
                else:
                    logger.error("本轮重试未能恢复联网")

            if last_login_success_time and (time.time() - last_login_success_time) > 6 * 3600:
                logger.info("超过 6 小时，主动刷新登录…")
                ensure_online_with_retry(session, config, portal_entry_url)
                last_login_success_time = time.time()
        except KeyboardInterrupt:
            logger.info("收到中断信号，退出守护循环。")
            break
        except Exception as exc:  # noqa: BLE001
            logger.exception("守护循环异常: %s", exc)
        time.sleep(interval)


def main() -> int:
    args = parse_args()
    config = resolve_config(args)
    require_requests()
    log_file = setup_logging(config.log_dir)
    if args.verbose:
        logger.setLevel(logging.DEBUG)

    logger.info(
        "================ 启动: %s ================",
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )
    logger.info("当前用户: %s", config.user_id)
    logger.info("日志文件: %s", log_file)

    if args.startup_delay > 0:
        logger.info("启动延迟 %d 秒 (等待系统/网络就绪)…", args.startup_delay)
        time.sleep(args.startup_delay)

    session = create_session()
    if args.once:
        if not args.force and is_online(session, config):
            logger.info("当前已在线，无需重复登录。")
            return 0
        return 0 if ensure_online_with_retry(session, config, args.portal_entry_url) else 1

    loop_guard(session, config, args.interval, args.portal_entry_url)
    return 0
