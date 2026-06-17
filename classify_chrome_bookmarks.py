#!/usr/bin/env python3
"""Classify Chrome bookmarks and optionally export them as a local webpage."""

from __future__ import annotations

import argparse
import copy
import html
import json
import os
import re
import shutil
import sys
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import OrderedDict
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
import requests

requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]


WINDOWS_EPOCH_OFFSET = 11644473600
DEFAULT_MISC_FOLDER = "未分类"
DEFAULT_ARCHIVE_FOLDER = "历史归档"
DEFAULT_KEEP_NAMES = {"Google"}
COMMUNITY_KEYWORDS = (
    "社区", "forum", "discord", "github", "gitlab", "掘金", "csdn",
    "教程", "文档", "docs", "doc", "feishu", "博客", "blog"
)
FINGERPRINT_CACHE = Path.cwd() / "bookmark_backups" / "platform_fingerprint_cache.json"
FINGERPRINT_TIMEOUT = 3.0
FINGERPRINT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) CodexBookmarkClassifier/1.0"
NEWAPI_MARKERS = (
    "newapi", "based oneapi", "console_setting", "/api/user/token",
    "/usage-logs", "/wallet", "/playground", "/keys", "subscription management",
    "api keys", "usage logs", "redeem codes", "token management"
)
SUB2API_MARKERS = (
    "sub2api", "sub2api - ai api gateway", "/purchase", "/subscriptions",
    "/api/v1/payment/webhook", "redeem-codes", "built-in payment",
    "subscription", "affiliate", "workspace", "usage dashboard"
)
NEWAPI_PATH_HINTS = ("/keys", "/playground", "/wallet", "/usage-logs", "/profile", "/console", "/panel", "/dashboard")
SUB2API_PATH_HINTS = ("/purchase", "/subscriptions", "/usage", "/affiliate", "/workspace", "/payment")
MANUAL_OVERRIDES = {
    "https://www.right.codes/home": ("非这两类", ["manual:right-code custom relay"]),
    "https://www.right.codes/models": ("非这两类", ["manual:right-code custom relay"]),
    "https://zhilianapi.com/console/playground": ("深度识别为 NewAPI", ["manual:user-corrected newapi"]),
    "https://linoapi.com.cn/pricing?provider=Grok%2B%2A%29&category=%E9%F%B3%E8%A7%86%E9%A2%91": ("深度识别为 NewAPI", ["manual:user-corrected newapi"]),
    "https://oken.ai/": ("非这两类", ["manual:price comparison site"]),
    "https://terminal.pub/": ("非这两类", ["manual:custom relay gateway"]),
    "https://fk.520952.xyz/": ("非这两类", ["manual:shop site"]),
    "https://ztest.ai/": ("非这两类", ["manual:relay verification site"]),
    "https://anyrouter.top/pricing": ("非这两类", ["manual:pricing page custom router"]),
    "https://www.univibe.cc/console/": ("非这两类", ["manual:univibe custom relay"]),
    "https://codex.miaomiaocode.com/purchase": ("非这两类", ["manual:miaomiaocode custom relay"]),
    "https://hoviwcode.cc/dashboard": ("非这两类", ["manual:aether custom relay"]),
    "https://foxcode.rjj.cc/usage": ("非这两类", ["manual:new-cli custom relay"]),
    "https://clearaigc.com/c/chatgpt": ("非这两类", ["manual:clearaigc discovery site"]),
    "https://freemodel.dev/dashboard/logs": ("非这两类", ["manual:freemodel custom relay"]),
    "https://pucoding.com/dashboard/api-keys": ("非这两类", ["manual:pucoding custom relay"]),
    "https://nvtokens.com/workspace": ("非这两类", ["manual:nexusvault trading platform"]),
}
MANUAL_EXCLUDED_DOMAINS = {
    "app.wandayun.com",
    "xiangzili.xyz",
    "fushengyunsuan.cn",
    "codexeasy.com",
    "www.codexeasy.com",
    "resourify.com",
    "aicoding.csdn.net",
}
MANUAL_PLATFORM_OVERRIDES_BY_DOMAIN = {
    "zhilianapi.com": ("深度识别为 NewAPI", ["manual:user-corrected newapi"]),
    "linoapi.com.cn": ("深度识别为 NewAPI", ["manual:user-corrected newapi"]),
    "yostoken.top": ("深度识别为 Sub2API", ["manual:user-corrected sub2api"]),
}
MANUAL_PUBLIC_BENEFIT_DOMAINS = {
    "anyrouter.top",
}
MANUAL_PINNED_DOMAINS = {
    "openai945.cn",
    "zhuozaiya.top",
    "aklhaode199.xyz",
    "codex2api.com",
    "www.codex2api.com",
}
MANUAL_PINNED_LINKS = [
    {
        "category": "ai中转站 / 我的常用",
        "title": "Codex2API - API 密钥",
        "url": "https://www.codex2api.com/keys",
        "domain": "www.codex2api.com",
        "fingerprint": {
            "platform": "深度识别为 Sub2API",
            "score": 99,
            "reasons": ["manual:pinned favorite codex2api"],
        },
    },
]
MANUAL_EXTRA_RELAY_LINKS = [
    {
        "category": "ai中转站 / 深度识别为 Sub2API",
        "title": "哟词元 - 仪表盘",
        "url": "https://yostoken.top/dashboard",
        "domain": "yostoken.top",
        "fingerprint": {
            "platform": "深度识别为 Sub2API",
            "score": 99,
            "reasons": ["manual:user-added sub2 entry"],
        },
    },
]


@dataclass(frozen=True)
class CategoryRule:
    folder_name: str
    keywords: tuple[str, ...] = ()
    domains: tuple[str, ...] = ()


RULES: tuple[CategoryRule, ...] = (
    CategoryRule(
        "开发社区",
        keywords=("社区", "掘金", "前端", "vue", "nuxt", "react", "javascript", "css", "html", "mdn"),
        domains=("juejin.cn", "juejin.im", "developer.mozilla.org", "bootcss.com", "csdn.net"),
    ),
    CategoryRule(
        "AI",
        keywords=("ai", "提示词", "gpt", "claude", "模型", "中转"),
        domains=("openai.com", "anthropic.com", "easemate.ai", "poe.com", "kimi.moonshot.cn"),
    ),
    CategoryRule(
        "内容平台",
        keywords=("公众号", "微信", "知乎", "博客", "文档", "动态"),
        domains=("mp.weixin.qq.com", "gitee.com", "shimo.im", "yuque.com", "kancloud.cn"),
    ),
    CategoryRule(
        "工作工具",
        keywords=("工具", "编辑", "调试", "swagger", "接口", "后台", "admin", "邮箱"),
        domains=("swagger.io",),
    ),
    CategoryRule(
        "学习资料",
        keywords=("学习", "教程", "guide", "文档", "参考", "three", "django", "input"),
        domains=("threejs.org", "docs.djangoproject.com"),
    ),
    CategoryRule(
        "求职面试",
        keywords=("面试", "兼职", "招聘", "工程师"),
        domains=("yuanjisong.com", "bosszhipin.com", "zhipin.com", "lagou.com"),
    ),
    CategoryRule(
        "设计素材",
        keywords=("去水印", "素材", "设计"),
        domains=("unsplash.com", "pexels.com"),
    ),
)


def chrome_now() -> str:
    unix_seconds = datetime.now(UTC).timestamp()
    return str(int((unix_seconds + WINDOWS_EPOCH_OFFSET) * 1_000_000))


def normalize_text(value: str) -> str:
    return re.sub(r"\s+", "", value).lower()


def keyword_matches(name: str, keyword: str) -> bool:
    lowered_name = name.lower()
    lowered_keyword = keyword.lower()
    if re.fullmatch(r"[a-z0-9_.+-]+", lowered_keyword):
        pattern = rf"(?<![a-z0-9]){re.escape(lowered_keyword)}(?![a-z0-9])"
        return re.search(pattern, lowered_name) is not None
    return lowered_keyword in normalize_text(name)


def get_domain(url: str) -> str:
    netloc = urlparse(url).netloc.lower()
    if netloc.startswith("www."):
        netloc = netloc[4:]
    return netloc


def match_category(name: str, url: str) -> str:
    domain = get_domain(url)
    for rule in RULES:
        if any(keyword_matches(name, keyword) for keyword in rule.keywords):
            return rule.folder_name
        if any(domain == item or domain.endswith(f".{item}") for item in rule.domains):
            return rule.folder_name
    return DEFAULT_MISC_FOLDER


def load_bookmarks(bookmarks_path: Path) -> dict:
    with bookmarks_path.open("r", encoding="utf-8") as fh:
        return json.load(fh, object_pairs_hook=OrderedDict)


def load_fingerprint_cache() -> dict[str, dict]:
    if not FINGERPRINT_CACHE.exists():
        return {}
    try:
        return json.loads(FINGERPRINT_CACHE.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def save_fingerprint_cache(cache: dict[str, dict]) -> None:
    FINGERPRINT_CACHE.parent.mkdir(parents=True, exist_ok=True)
    FINGERPRINT_CACHE.write_text(json.dumps(cache, ensure_ascii=False, indent=2), encoding="utf-8")


def backup_bookmarks(bookmarks_path: Path, backup_dir: Path) -> Path:
    backup_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    target = backup_dir / f"Bookmarks.backup-{timestamp}.json"
    shutil.copy2(bookmarks_path, target)
    return target


def next_id(data: dict) -> str:
    max_value = 0

    def walk(node: dict) -> None:
        nonlocal max_value
        node_id = node.get("id")
        if isinstance(node_id, str) and node_id.isdigit():
            max_value = max(max_value, int(node_id))
        for child in node.get("children", []):
            walk(child)

    for root in data.get("roots", {}).values():
        if isinstance(root, dict):
            walk(root)
    return str(max_value + 1)


def make_folder(data: dict, name: str) -> dict:
    now = chrome_now()
    return OrderedDict(
        (
            ("children", []),
            ("date_added", now),
            ("date_last_used", "0"),
            ("date_modified", now),
            ("guid", str(uuid.uuid4())),
            ("id", next_id(data)),
            ("name", name),
            ("type", "folder"),
        )
    )


def summarize_bookmark_bar(children: Iterable[dict]) -> tuple[int, int]:
    total = 0
    direct_urls = 0
    for item in children:
        total += 1
        if item.get("type") == "url":
            direct_urls += 1
    return total, direct_urls


def organize_bookmark_bar(
    data: dict,
    keep_names: set[str],
    archive_folder_name: str,
) -> tuple[dict, dict[str, list[dict]]]:
    result = copy.deepcopy(data)
    bar = result["roots"]["bookmark_bar"]
    original_children = list(bar.get("children", []))
    grouped: dict[str, list[dict]] = OrderedDict()
    preserved: list[dict] = []

    for item in original_children:
        item_type = item.get("type")
        if item_type == "folder":
            grouped.setdefault(archive_folder_name, []).append(item)
            continue

        if item_type != "url":
            preserved.append(item)
            continue

        if item.get("name") in keep_names:
            preserved.append(item)
            continue

        category = match_category(item.get("name", ""), item.get("url", ""))
        grouped.setdefault(category, []).append(item)

    new_children = list(preserved)
    for folder_name, items in grouped.items():
        if not items:
            continue
        folder = make_folder(result, folder_name)
        folder["children"] = items
        folder["date_modified"] = chrome_now()
        new_children.append(folder)

    bar["children"] = new_children
    bar["date_modified"] = chrome_now()
    return result, grouped


def flatten_children(children: Iterable[dict], folder_path: tuple[str, ...] = ()) -> list[dict]:
    rows: list[dict] = []
    for item in children:
        item_type = item.get("type")
        if item_type == "url":
            category = " / ".join(folder_path) if folder_path else match_category(item.get("name", ""), item.get("url", ""))
            rows.append(
                {
                    "category": category,
                    "title": item.get("name", "").strip() or "(未命名)",
                    "url": item.get("url", ""),
                    "domain": get_domain(item.get("url", "")),
                }
            )
            continue

        if item_type == "folder":
            folder_name = item.get("name", "").strip() or DEFAULT_ARCHIVE_FOLDER
            rows.extend(flatten_children(item.get("children", []), folder_path + (folder_name,)))
    return rows


def walk_folders(children: Iterable[dict], folder_path: tuple[str, ...] = ()) -> Iterable[tuple[tuple[str, ...], dict]]:
    for item in children:
        if item.get("type") != "folder":
            continue
        folder_name = item.get("name", "").strip() or DEFAULT_ARCHIVE_FOLDER
        current_path = folder_path + (folder_name,)
        yield current_path, item
        yield from walk_folders(item.get("children", []), current_path)


def find_folder_by_name(bookmarks_data: dict, folder_name: str) -> tuple[tuple[str, ...], dict] | None:
    roots = bookmarks_data["roots"]["bookmark_bar"].get("children", [])
    target = folder_name.casefold()
    for path, node in walk_folders(roots):
        if path[-1].casefold() == target:
            return path, node
    return None


def filter_rows_to_community(rows: list[dict]) -> list[dict]:
    filtered: list[dict] = []
    for row in rows:
        combined = f"{row['title']} {row['url']} {row['domain']}".lower()
        if any(keyword.lower() in combined for keyword in COMMUNITY_KEYWORDS):
            filtered.append(row)
    return filtered


def fetch_url_text(url: str) -> str:
    headers = {
        "User-Agent": FINGERPRINT_USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
    }
    try:
        response = requests.get(
            url,
            headers=headers,
            timeout=FINGERPRINT_TIMEOUT,
            allow_redirects=True,
            verify=False,
        )
        response.raise_for_status()
        response.encoding = response.encoding or "utf-8"
        return response.text[:80_000]
    except requests.RequestException:
        request = Request(url, headers=headers)
        with urlopen(request, timeout=FINGERPRINT_TIMEOUT) as response:
            content_type = response.headers.get_content_charset() or "utf-8"
            body = response.read(80_000)
            return body.decode(content_type, errors="ignore")


def candidate_probe_urls(url: str) -> list[str]:
    parsed = urlparse(url)
    root = f"{parsed.scheme}://{parsed.netloc}"
    candidates = [url]
    for suffix in ("", "/", "/login", "/signin", "/dashboard", "/console", "/keys", "/purchase", "/subscriptions"):
        candidate = root + suffix
        if candidate not in candidates:
            candidates.append(candidate)
    return candidates


def candidate_probe_api_urls(url: str) -> list[tuple[str, str]]:
    parsed = urlparse(url)
    root = f"{parsed.scheme}://{parsed.netloc}"
    return [
        ("newapi-status", root + "/api/status"),
        ("sub2api-public-settings", root + "/api/v1/settings/public"),
    ]


def score_platform_from_text(text: str, url: str) -> tuple[str, int, list[str]]:
    lowered = text.lower()
    parsed = urlparse(url)
    path = parsed.path.lower()
    reasons: list[str] = []
    newapi_score = 0
    sub2_score = 0

    title_match = re.search(r"<title>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
    if title_match:
        title_text = title_match.group(1).strip().lower()
        if "sub2api" in title_text or "ai api gateway" in title_text:
            sub2_score += 6
            reasons.append(f"title:{title_text[:80]}")
        if "new api" in title_text or "newapi" in title_text:
            newapi_score += 6
            reasons.append(f"title:{title_text[:80]}")

    for marker in NEWAPI_MARKERS:
        if marker in lowered:
            newapi_score += 3
            reasons.append(f"newapi:{marker}")
    for marker in SUB2API_MARKERS:
        if marker in lowered:
            sub2_score += 3
            reasons.append(f"sub2:{marker}")

    if any(hint in path for hint in NEWAPI_PATH_HINTS):
        newapi_score += 1
        reasons.append(f"newapi-path:{path}")
    if any(hint in path for hint in SUB2API_PATH_HINTS):
        sub2_score += 1
        reasons.append(f"sub2-path:{path}")

    if "newapi" in parsed.netloc.lower():
        newapi_score += 4
        reasons.append("newapi-domain")
    if "sub2" in parsed.netloc.lower():
        sub2_score += 4
        reasons.append("sub2-domain")

    if newapi_score == 0 and sub2_score == 0:
        return "未识别", 0, reasons
    if newapi_score >= sub2_score + 3:
        return "深度识别为 NewAPI", newapi_score, reasons
    if sub2_score >= newapi_score + 3:
        return "深度识别为 Sub2API", sub2_score, reasons
    return "待人工确认", max(newapi_score, sub2_score), reasons


def score_platform_from_api(payload: str, probe_type: str) -> tuple[str, int, list[str]]:
    lowered = payload.lower()
    if probe_type == "newapi-status":
        if any(marker in lowered for marker in ("system_name", "quota_per_unit", "turnstile_site_key", "docs_link", "version")):
            return "深度识别为 NewAPI", 12, ["api:newapi-status"]
    if probe_type == "sub2api-public-settings":
        if any(marker in lowered for marker in ("registration_enabled", "promo_code_enabled", "totp_enabled", "login_agreement_enabled")):
            return "深度识别为 Sub2API", 12, ["api:sub2api-public-settings"]
    return "未识别", 0, []


def fingerprint_row(row: dict, cache: dict[str, dict]) -> dict:
    url = row["url"]
    domain = row.get("domain") or get_domain(url)
    if domain in MANUAL_PLATFORM_OVERRIDES_BY_DOMAIN:
        platform, reasons = MANUAL_PLATFORM_OVERRIDES_BY_DOMAIN[domain]
        result = {
            "platform": platform,
            "score": 99,
            "reasons": reasons,
        }
        cache[url] = result
        return result
    if url in MANUAL_OVERRIDES:
        platform, reasons = MANUAL_OVERRIDES[url]
        result = {
            "platform": platform,
            "score": 99,
            "reasons": reasons,
        }
        cache[url] = result
        return result
    if url in cache:
        return cache[url]

    result = {
        "platform": "探测失败",
        "score": 0,
        "reasons": [],
    }
    best_result = result
    for probe_type, api_url in candidate_probe_api_urls(url):
        try:
            payload = fetch_url_text(api_url)
            platform, score, reasons = score_platform_from_api(payload, probe_type)
            if score > best_result["score"]:
                best_result = {
                    "platform": platform,
                    "score": score,
                    "reasons": reasons,
                }
            if platform in {"深度识别为 NewAPI", "深度识别为 Sub2API"}:
                cache[url] = best_result
                return best_result
        except (HTTPError, URLError, TimeoutError, OSError):
            pass

    for candidate in candidate_probe_urls(url):
        try:
            text = fetch_url_text(candidate)
            platform, score, reasons = score_platform_from_text(text, candidate)
            candidate_result = {
                "platform": platform,
                "score": score,
                "reasons": reasons[:8],
            }
            if candidate_result["score"] > best_result["score"]:
                best_result = candidate_result
            if platform in {"深度识别为 NewAPI", "深度识别为 Sub2API"}:
                best_result = candidate_result
                break
        except (HTTPError, URLError, TimeoutError, OSError) as exc:
            best_result = best_result if best_result["score"] else {
                "platform": "探测失败",
                "score": 0,
                "reasons": [str(exc)],
            }

    if best_result["score"] == 0 and best_result["platform"] == "未识别":
        best_result = {
            "platform": "待人工确认",
            "score": 0,
            "reasons": ["未命中已知指纹"],
        }

    result = best_result

    cache[url] = result
    return result


def enrich_rows_with_fingerprints(rows: list[dict]) -> list[dict]:
    cache = load_fingerprint_cache()
    updated_rows = [dict(row) for row in rows]

    with ThreadPoolExecutor(max_workers=12) as executor:
        future_map = {executor.submit(fingerprint_row, row, cache): row for row in updated_rows}
        for future in as_completed(future_map):
            row = future_map[future]
            try:
                row["fingerprint"] = future.result()
            except Exception as exc:  # pragma: no cover
                row["fingerprint"] = {
                    "platform": "探测失败",
                    "score": 0,
                    "reasons": [str(exc)],
                }

    save_fingerprint_cache(cache)
    return updated_rows


def normalize_platform_name(platform: str | None) -> str:
    value = (platform or "").strip().lower()
    if "newapi" in value or "new api" in value:
        return "newapi"
    if "sub2api" in value or "sub2" in value:
        return "sub2api"
    if "非这两类" in (platform or "") or "other" in value:
        return "other"
    if "待人工确认" in (platform or "") or "review" in value:
        return "review"
    if "探测失败" in (platform or "") or "failed" in value:
        return "failed"
    if "未识别" in (platform or "") or "unknown" in value:
        return "unknown"
    return value


def is_price_comparison_row(row: dict) -> bool:
    fingerprint = row.get("fingerprint", {})
    reasons = [str(item).lower() for item in fingerprint.get("reasons", [])]
    combined = f"{row.get('title', '')} {row.get('url', '')} {row.get('domain', '')}".lower()
    domain = (row.get("domain") or "").lower()
    comparison_tokens = (
        "比价", "一键比价", "订阅比价", "price comparison", "compare",
        "comparison", "aggregator", "aibijia",
    )
    reason_tokens = (
        "price comparison", "comparison site", "比价",
    )
    if any(token in combined for token in comparison_tokens):
        return True
    if any(token in domain for token in ("aibijia",)):
        return True
    if any(token in reason for reason in reasons for token in reason_tokens):
        return True
    return False


def is_public_benefit_row(row: dict) -> bool:
    fingerprint = row.get("fingerprint", {})
    reasons = [str(item).lower() for item in fingerprint.get("reasons", [])]
    combined = f"{row.get('title', '')} {row.get('url', '')} {row.get('domain', '')}".lower()
    domain = (row.get("domain") or "").lower()
    public_tokens = (
        "公益", "签到", "积分", "每日领", "白嫖", "免费额度", "薅羊毛",
        "签到领取", "积分兑换", "做任务", "l站积分", "免费 token",
        "daily bonus", "check-in", "credits", "free tier", "free token",
    )
    if domain in MANUAL_PUBLIC_BENEFIT_DOMAINS:
        return True
    if any(token in combined for token in public_tokens):
        return True
    if any(token in reason for reason in reasons for token in ("公益", "积分", "签到", "free token", "credits", "check-in")):
        return True
    return False


def is_manually_excluded_domain(domain: str) -> bool:
    normalized = (domain or "").strip().lower()
    return any(
        normalized == blocked or normalized.endswith(f".{blocked}")
        for blocked in MANUAL_EXCLUDED_DOMAINS
    )


def is_pinned_domain(domain: str) -> bool:
    normalized = (domain or "").strip().lower()
    return any(
        normalized == pinned or normalized.endswith(f".{pinned}")
        for pinned in MANUAL_PINNED_DOMAINS
    )


def filter_out_failed_rows(rows: list[dict]) -> list[dict]:
    filtered: list[dict] = []
    for row in rows:
        fingerprint = row.get("fingerprint", {})
        platform = normalize_platform_name(fingerprint.get("platform"))
        if platform in {"failed", "探测失败", "探测错误", "探测异常"}:
            continue
        filtered.append(row)
    return filtered


def filter_rows_to_ai_relays(rows: list[dict]) -> list[dict]:
    relay_path_markers = (
        "/dashboard", "/console", "/panel", "/keys", "/api-keys", "/token",
        "/tokens", "/wallet", "/usage", "/playground", "/purchase",
        "/subscriptions", "/topup", "/redeem", "/workspace", "/models",
    )
    excluded_path_markers = (
        "/docs", "/doc", "/documentation", "/wiki", "/blog", "/news",
        "/post", "/article", "/community", "/forum", "/help", "/guide",
    )
    weak_entry_path_markers = (
        "/cat/", "/category/", "/tag/", "/tags/", "/image", "/images", "ai-image",
        "/article/", "/post/", "/rankings", "/discover", "/channel/",
    )
    relay_text_markers = (
        "api key", "api keys", "openai", "claude", "gemini", "gpt",
        "模型", "中转", "令牌", "token", "额度", "充值", "订阅",
        "用量", "控制台", "控制面板", "dashboard", "console", "playground",
    )
    exclude_text_markers = (
        "github", "discord", "forum", "blog", "csdn", "feishu", "wiki",
        "教程", "文档", "社区", "资讯", "导航", "price comparison",
        "comparison", "verification", "shop site", "trading platform",
    )
    relay_reason_markers = (
        "custom relay", "relay gateway", "custom router", "gateway",
        "api:newapi-status", "api:sub2api-public-settings",
    )
    exclude_reason_markers = (
        "price comparison", "verification site", "discovery site",
        "shop site", "trading platform",
    )

    filtered: list[dict] = []
    for row in rows:
        fingerprint = row.get("fingerprint", {})
        platform = normalize_platform_name(fingerprint.get("platform"))
        reasons = [str(item).lower() for item in fingerprint.get("reasons", [])]
        combined = f"{row.get('title', '')} {row.get('url', '')} {row.get('domain', '')}".lower()
        path = urlparse(row.get("url", "")).path.lower()
        domain = (row.get("domain") or "").lower()

        if is_manually_excluded_domain(domain):
            continue

        if is_price_comparison_row(row):
            filtered.append(row)
            continue

        if any(marker in path for marker in excluded_path_markers):
            continue

        if any(marker in combined for marker in ("feishu", "github", "discord", "documentation", "docs.", "wiki")):
            continue

        if any(marker in path for marker in weak_entry_path_markers):
            if not any(marker in path for marker in ("/dashboard", "/console", "/panel", "/keys", "/api-keys")):
                continue

        if platform in {"newapi", "sub2api"}:
            filtered.append(row)
            continue

        if any(marker in reason for reason in reasons for marker in exclude_reason_markers):
            continue

        if any(marker in reason for reason in reasons for marker in relay_reason_markers):
            filtered.append(row)
            continue

        if any(marker in combined for marker in exclude_text_markers):
            if not any(marker in combined for marker in ("中转", "api key", "dashboard", "console", "token", "充值", "订阅")):
                continue

        if any(marker in path for marker in relay_path_markers):
            filtered.append(row)
            continue

        if any(marker in combined for marker in relay_text_markers):
            filtered.append(row)
            continue

        if platform in {"review", "failed", "unknown"} and any(token in combined for token in ("api", "gpt", "claude", "gemini")):
            filtered.append(row)

    return filtered


def relay_entry_priority(row: dict) -> int:
    url = row.get("url", "")
    parsed = urlparse(url)
    path = parsed.path.lower()
    combined = f"{row.get('title', '')} {url} {row.get('domain', '')}".lower()
    score = 0

    if is_pinned_domain(row.get("domain", "")):
        score += 120

    if path in {"", "/", "/home", "/index", "/login", "/signin"}:
        score += 18
    if any(token in path for token in ("/dashboard", "/console", "/panel")):
        score += 40
    if any(token in path for token in ("/keys", "/api-keys", "/token", "/tokens")):
        score += 36
    if any(token in path for token in ("/wallet", "/usage", "/playground", "/workspace", "/models")):
        score += 26
    if any(token in path for token in ("/purchase", "/subscriptions", "/topup", "/redeem", "/pricing")):
        score += 16
    if any(token in combined for token in ("控制台", "dashboard", "console", "api key", "token")):
        score += 10
    if any(token in path for token in ("/docs", "/doc", "/documentation", "/wiki", "/blog", "/forum", "/community")):
        score -= 50

    fingerprint = row.get("fingerprint", {})
    score += int(fingerprint.get("score", 0) or 0) * 2
    return score


def dedupe_relay_rows(rows: list[dict]) -> list[dict]:
    best_by_domain: dict[str, dict] = {}
    for row in rows:
        domain = row.get("domain") or get_domain(row.get("url", ""))
        existing = best_by_domain.get(domain)
        current_key = (
            relay_entry_priority(row),
            int(row.get("fingerprint", {}).get("score", 0) or 0),
            len(str(row.get("url", ""))),
        )
        if not existing:
            best_by_domain[domain] = row
            continue
        existing_key = (
            relay_entry_priority(existing),
            int(existing.get("fingerprint", {}).get("score", 0) or 0),
            len(str(existing.get("url", ""))),
        )
        if current_key > existing_key:
            best_by_domain[domain] = row
    return sorted(best_by_domain.values(), key=lambda item: (item.get("domain", ""), item.get("title", "").lower()))


def build_relay_assessment(row: dict) -> dict[str, object]:
    fingerprint = row.get("fingerprint", {})
    platform = normalize_platform_name(fingerprint.get("platform"))
    raw_score = int(fingerprint.get("score", 0) or 0)
    reasons = [str(item).lower() for item in fingerprint.get("reasons", [])]
    url = row.get("url", "")
    path = urlparse(url).path.lower()
    combined = f"{row.get('title', '')} {url} {row.get('domain', '')}".lower()
    is_comparison = is_price_comparison_row(row)
    is_public_benefit = is_public_benefit_row(row)
    is_pinned = is_pinned_domain(row.get("domain", ""))

    trust_score = raw_score * 6
    if platform == "newapi":
        trust_score += 18
    elif platform == "sub2api":
        trust_score += 16
    elif platform == "review":
        trust_score += 4
    elif platform == "failed":
        trust_score -= 18
    elif platform == "unknown":
        trust_score -= 8

    if any(marker in reasons for marker in ("api:newapi-status", "api:sub2api-public-settings")):
        trust_score += 12
    if any("custom relay" in reason or "relay gateway" in reason or "custom router" in reason for reason in reasons):
        trust_score += 10
    if any(token in path for token in ("/dashboard", "/console", "/panel", "/keys", "/api-keys")):
        trust_score += 10
    if any(token in path for token in ("/docs", "/doc", "/documentation", "/wiki")):
        trust_score -= 24
    if any(token in combined for token in ("github", "discord", "wiki", "documentation", "feishu")):
        trust_score -= 24
    if is_comparison:
        trust_score -= 12
    if is_public_benefit:
        trust_score -= 8
    if is_pinned:
        trust_score += 6

    trust_score = max(0, min(100, trust_score))

    if is_pinned:
        entry_type = "我的常用"
    elif is_public_benefit:
        entry_type = "公益入口"
    elif is_comparison:
        entry_type = "比价入口"
    elif any(token in path for token in ("/dashboard", "/console", "/panel")):
        entry_type = "控制台入口"
    elif any(token in path for token in ("/keys", "/api-keys", "/token", "/tokens")):
        entry_type = "Key 管理"
    elif any(token in path for token in ("/usage", "/wallet", "/workspace")):
        entry_type = "用量入口"
    elif any(token in path for token in ("/purchase", "/subscriptions", "/topup", "/redeem", "/pricing")):
        entry_type = "购买入口"
    elif any(token in path for token in ("/models", "/playground")):
        entry_type = "模型入口"
    else:
        entry_type = "站点首页"

    if trust_score >= 80:
        trust_label = "高可信"
        trust_class = "is-trust-high"
    elif trust_score >= 60:
        trust_label = "可优先看"
        trust_class = "is-trust-mid"
    elif trust_score >= 40:
        trust_label = "待复核"
        trust_class = "is-trust-low"
    else:
        trust_label = "高风险"
        trust_class = "is-trust-risk"

    risk_flags: list[str] = []
    if platform == "failed":
        risk_flags.append("探测失败")
    if platform in {"review", "unknown"}:
        risk_flags.append("特征偏弱")
    if is_pinned:
        risk_flags.append("常用置顶")
    if is_public_benefit:
        risk_flags.append("签到/积分型")
    if is_comparison:
        risk_flags.append("聚合比价")
    if any(token in path for token in ("/purchase", "/subscriptions", "/pricing")) and not any(
        token in path for token in ("/dashboard", "/console", "/panel", "/keys", "/api-keys")
    ):
        risk_flags.append("偏购买入口")
    if raw_score and raw_score < 6:
        risk_flags.append("证据较少")
    if any(token in reasons_text for token in ("price comparison", "verification site", "discovery site", "trading platform") for reasons_text in reasons):
        risk_flags.append("非核心入口")
    if not risk_flags:
        risk_flags.append("低风险")

    return {
        "entry_type": entry_type,
        "trust_score": trust_score,
        "trust_label": trust_label,
        "trust_class": trust_class,
        "risk_label": risk_flags[0],
    }


def write_bookmarks(bookmarks_path: Path, data: dict) -> None:
    with bookmarks_path.open("w", encoding="utf-8", newline="\n") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
        fh.write("\n")


def print_preview(
    original_children: list[dict],
    grouped: dict[str, list[dict]],
    keep_names: set[str],
    archive_folder_name: str,
) -> None:
    total, direct_urls = summarize_bookmark_bar(original_children)
    print(f"书签栏原始项目数: {total}")
    print(f"书签栏直接暴露的网址数: {direct_urls}")
    print(f"保留在顶栏的固定书签: {', '.join(sorted(keep_names)) or '无'}")
    print("")
    print("分类预览:")
    if not grouped:
        print("  没有可整理的条目。")
        return

    for folder_name, items in grouped.items():
        label = f"{folder_name} ({len(items)})"
        if folder_name == archive_folder_name:
            label += " - 现有文件夹将整体收进去"
        print(f"- {label}")
        for item in items[:8]:
            name = item.get("name", "").strip() or "(未命名)"
            print(f"    · {name}")
        if len(items) > 8:
            print(f"    · ... 还有 {len(items) - 8} 项")


def render_bookmarks_html(rows: list[dict], source_name: str) -> str:
    grouped: OrderedDict[str, list[dict]] = OrderedDict()
    for row in sorted(rows, key=lambda item: (item["category"], item["title"].lower())):
        grouped.setdefault(row["category"], []).append(row)

    total_categories = len(grouped)
    top_categories = sorted(grouped.items(), key=lambda entry: len(entry[1]), reverse=True)[:6]
    chips = "".join(
        f'<button class="filter-chip" type="button" data-chip="{html.escape(category.lower())}">{html.escape(category)} <span>{len(items)}</span></button>'
        for category, items in top_categories
    )

    cards: list[str] = []
    for category, items in grouped.items():
        links = []
        for row in items:
            title = html.escape(row["title"])
            url = html.escape(row["url"], quote=True)
            domain = html.escape(row["domain"] or "未知来源")
            short_domain = html.escape((row["domain"] or "未知来源").replace("www.", ""))
            links.append(
                f"""
                <li class="bookmark-item" data-title="{title.lower()}" data-domain="{domain.lower()}">
                  <a class="bookmark-link" href="{url}" target="_blank" rel="noopener noreferrer">
                    <span class="bookmark-title">{title}</span>
                    <span class="bookmark-arrow">↗</span>
                  </a>
                  <div class="bookmark-meta">
                    <span class="bookmark-domain">{domain}</span>
                    <span class="bookmark-badge">{short_domain}</span>
                  </div>
                </li>
                """.strip()
            )

        cards.append(
            f"""
            <section class="category-card" data-category="{html.escape(category.lower())}">
              <div class="category-header">
                <div class="category-title-block">
                  <span class="category-kicker">分类</span>
                  <h2>{html.escape(category)}</h2>
                </div>
                <span class="category-count">{len(items)} 个链接</span>
              </div>
              <ul class="bookmark-list">
                {''.join(links)}
              </ul>
            </section>
            """.strip()
        )

    generated_at = html.escape(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    source_label = html.escape(source_name)
    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>开发者导航</title>
  <style>
    :root {{
      --bg: #0b1220;
      --bg-soft: #111a2d;
      --panel: rgba(14, 23, 39, 0.84);
      --panel-2: rgba(16, 27, 46, 0.92);
      --line: rgba(148, 163, 184, 0.16);
      --line-strong: rgba(96, 165, 250, 0.24);
      --text: #e5eefc;
      --muted: #8ea3c3;
      --accent: #5eead4;
      --accent-2: #60a5fa;
      --accent-3: #a78bfa;
      --chip: rgba(96, 165, 250, 0.12);
      --shadow: 0 24px 60px rgba(2, 8, 23, 0.46);
      --mono: "Cascadia Code", "JetBrains Mono", "Fira Code", Consolas, monospace;
      --sans: "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif;
    }}

    * {{
      box-sizing: border-box;
    }}

    html {{
      color-scheme: dark;
    }}

    body {{
      margin: 0;
      min-height: 100vh;
      color: var(--text);
      font-family: var(--sans);
      background:
        radial-gradient(circle at top left, rgba(96, 165, 250, 0.16), transparent 22%),
        radial-gradient(circle at 88% 10%, rgba(94, 234, 212, 0.14), transparent 18%),
        linear-gradient(180deg, #08111f 0%, #0b1220 46%, #0a1322 100%);
    }}

    body::before {{
      content: "";
      position: fixed;
      inset: 0;
      pointer-events: none;
      background-image:
        linear-gradient(rgba(148, 163, 184, 0.06) 1px, transparent 1px),
        linear-gradient(90deg, rgba(148, 163, 184, 0.06) 1px, transparent 1px);
      background-size: 28px 28px;
      mask-image: linear-gradient(180deg, rgba(0,0,0,0.72), transparent 92%);
    }}

    .page {{
      width: min(1400px, calc(100vw - 28px));
      margin: 0 auto;
      padding: 26px 0 46px;
    }}

    .hero {{
      position: relative;
      overflow: hidden;
      display: grid;
      grid-template-columns: minmax(0, 1.35fr) minmax(280px, 0.65fr);
      gap: 18px;
      padding: 28px;
      border-radius: 24px;
      background:
        linear-gradient(180deg, rgba(12, 20, 35, 0.94), rgba(10, 18, 32, 0.86)),
        linear-gradient(120deg, rgba(96, 165, 250, 0.08), rgba(94, 234, 212, 0.06));
      border: 1px solid var(--line);
      box-shadow: var(--shadow);
    }}

    .hero::after {{
      content: "";
      position: absolute;
      right: -40px;
      top: -40px;
      width: 220px;
      height: 220px;
      border-radius: 50%;
      background: radial-gradient(circle, rgba(96, 165, 250, 0.18), transparent 68%);
      filter: blur(10px);
      pointer-events: none;
    }}

    .hero-copy,
    .hero-panel {{
      position: relative;
      z-index: 1;
    }}

    .hero-eyebrow {{
      display: inline-flex;
      align-items: center;
      gap: 10px;
      padding: 8px 12px;
      border-radius: 999px;
      background: rgba(94, 234, 212, 0.08);
      border: 1px solid rgba(94, 234, 212, 0.22);
      color: var(--accent);
      font-family: var(--mono);
      font-size: 12px;
      letter-spacing: 0.08em;
      text-transform: uppercase;
    }}

    .hero h1 {{
      margin: 14px 0 0;
      font-size: clamp(34px, 5vw, 60px);
      line-height: 0.98;
      letter-spacing: -0.04em;
      max-width: 11ch;
    }}

    .hero p {{
      margin: 14px 0 0;
      max-width: 760px;
      color: var(--muted);
      font-size: 16px;
      line-height: 1.75;
    }}

    .hero-meta {{
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      margin-top: 18px;
    }}

    .meta-pill {{
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 9px 12px;
      border-radius: 999px;
      background: rgba(148, 163, 184, 0.08);
      border: 1px solid rgba(148, 163, 184, 0.14);
      color: var(--muted);
      font-size: 13px;
      font-family: var(--mono);
    }}

    .hero-panel {{
      display: grid;
      gap: 12px;
      align-content: start;
    }}

    .stats-card {{
      padding: 18px;
      border-radius: 18px;
      background: linear-gradient(135deg, rgba(17, 27, 46, 0.98), rgba(10, 18, 32, 0.92));
      border: 1px solid var(--line-strong);
    }}

    .stats-card small,
    .stat-box span {{
      display: block;
      color: var(--muted);
      font-family: var(--mono);
      font-size: 11px;
      letter-spacing: 0.08em;
      text-transform: uppercase;
    }}

    .stats-card strong {{
      display: block;
      margin: 10px 0 6px;
      font-size: clamp(32px, 4vw, 48px);
      line-height: 1;
      color: #f8fbff;
    }}

    .stats-grid {{
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 12px;
    }}

    .stat-box {{
      padding: 16px;
      border-radius: 18px;
      background: rgba(17, 27, 46, 0.88);
      border: 1px solid var(--line);
    }}

    .stat-box strong {{
      display: block;
      margin-top: 8px;
      font-size: 24px;
      line-height: 1;
    }}

    .toolbar {{
      display: grid;
      grid-template-columns: minmax(0, 1fr) 280px;
      gap: 18px;
      margin: 20px 0;
    }}

    .toolbar-left,
    .result-summary {{
      border-radius: 22px;
      background: var(--panel);
      border: 1px solid var(--line);
      box-shadow: var(--shadow);
    }}

    .toolbar-left {{
      padding: 18px;
      display: grid;
      gap: 14px;
    }}

    .toolbar-title {{
      color: var(--muted);
      font-family: var(--mono);
      font-size: 12px;
      letter-spacing: 0.08em;
      text-transform: uppercase;
    }}

    .search-shell {{
      display: flex;
      align-items: center;
      gap: 12px;
      padding: 14px 16px;
      border-radius: 18px;
      background: rgba(6, 11, 20, 0.45);
      border: 1px solid rgba(148, 163, 184, 0.12);
    }}

    .search-icon {{
      display: inline-grid;
      place-items: center;
      width: 36px;
      height: 36px;
      border-radius: 12px;
      background: linear-gradient(135deg, rgba(96, 165, 250, 0.18), rgba(94, 234, 212, 0.12));
      color: var(--accent);
      font-family: var(--mono);
      font-size: 15px;
    }}

    .search-box {{
      width: 100%;
      padding: 0;
      border: 0;
      background: transparent;
      color: var(--text);
      font-size: 15px;
      outline: none;
    }}

    .search-box::placeholder {{
      color: #6981a5;
    }}

    .chip-row {{
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
    }}

    .filter-chip {{
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 9px 12px;
      border: 1px solid rgba(148, 163, 184, 0.12);
      border-radius: 999px;
      background: var(--chip);
      color: #b7c7e3;
      font-family: var(--mono);
      font-size: 12px;
      cursor: pointer;
      transition: border-color 0.15s ease, background 0.15s ease, color 0.15s ease, transform 0.15s ease;
    }}

    .filter-chip span {{
      color: var(--accent);
    }}

    .filter-chip:hover,
    .filter-chip.active {{
      transform: translateY(-1px);
      background: rgba(94, 234, 212, 0.12);
      border-color: rgba(94, 234, 212, 0.32);
      color: #ecfeff;
    }}

    .result-summary {{
      padding: 18px;
      display: grid;
      gap: 10px;
      align-content: center;
    }}

    .result-summary strong {{
      display: block;
      font-size: 30px;
      line-height: 1;
      color: #f8fbff;
    }}

    .result-summary span,
    .result-summary div:last-child {{
      color: var(--muted);
      font-size: 14px;
    }}

    .grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
      gap: 18px;
    }}

    .category-card {{
      position: relative;
      overflow: hidden;
      padding: 18px;
      border-radius: 22px;
      background: var(--panel-2);
      border: 1px solid var(--line);
      box-shadow: var(--shadow);
    }}

    .category-card::before {{
      content: "";
      position: absolute;
      inset: 0 auto 0 0;
      width: 3px;
      background: linear-gradient(180deg, var(--accent-2), var(--accent));
      opacity: 0.92;
    }}

    .category-header {{
      display: flex;
      align-items: start;
      justify-content: space-between;
      gap: 12px;
      margin-bottom: 14px;
      padding-left: 6px;
    }}

    .category-kicker {{
      display: inline-block;
      margin-bottom: 8px;
      color: var(--accent);
      font-family: var(--mono);
      font-size: 11px;
      letter-spacing: 0.08em;
      text-transform: uppercase;
    }}

    .category-header h2 {{
      margin: 0;
      font-size: 22px;
      line-height: 1.2;
      letter-spacing: -0.02em;
      word-break: break-word;
    }}

    .category-count {{
      flex: 0 0 auto;
      padding: 7px 10px;
      border-radius: 999px;
      background: rgba(96, 165, 250, 0.12);
      border: 1px solid rgba(96, 165, 250, 0.14);
      color: #bfdbfe;
      font-family: var(--mono);
      font-size: 12px;
      white-space: nowrap;
    }}

    .bookmark-list {{
      list-style: none;
      margin: 0;
      padding: 0;
      display: grid;
      gap: 10px;
    }}

    .bookmark-item {{
      padding: 13px 14px;
      border-radius: 16px;
      background: rgba(8, 14, 24, 0.36);
      border: 1px solid rgba(148, 163, 184, 0.08);
      transition: border-color 0.15s ease, transform 0.15s ease, background 0.15s ease;
    }}

    .bookmark-item:hover {{
      transform: translateY(-1px);
      background: rgba(10, 18, 32, 0.74);
      border-color: rgba(94, 234, 212, 0.2);
    }}

    .bookmark-link {{
      display: flex;
      align-items: start;
      justify-content: space-between;
      gap: 12px;
      text-decoration: none;
      color: var(--text);
      line-height: 1.45;
      font-size: 15px;
      font-weight: 600;
    }}

    .bookmark-link:hover {{
      color: #ffffff;
    }}

    .bookmark-title {{
      flex: 1 1 auto;
      min-width: 0;
      word-break: break-word;
    }}

    .bookmark-arrow {{
      flex: 0 0 auto;
      color: var(--accent);
      opacity: 0.8;
      font-family: var(--mono);
    }}

    .bookmark-meta {{
      margin-top: 9px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
    }}

    .bookmark-domain {{
      flex: 1 1 auto;
      color: var(--muted);
      font-family: var(--mono);
      font-size: 11px;
      word-break: break-all;
    }}

    .bookmark-badge {{
      flex: 0 0 auto;
      max-width: 44%;
      padding: 5px 9px;
      border-radius: 999px;
      background: rgba(167, 139, 250, 0.12);
      color: #d8b4fe;
      font-family: var(--mono);
      font-size: 11px;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }}

    .empty-state {{
      display: none;
      margin-top: 20px;
      padding: 26px;
      border-radius: 22px;
      background: var(--panel);
      border: 1px dashed rgba(148, 163, 184, 0.22);
      color: var(--muted);
      text-align: center;
      box-shadow: var(--shadow);
    }}

    .empty-state.visible {{
      display: block;
    }}

    @media (max-width: 980px) {{
      .hero,
      .toolbar {{
        grid-template-columns: 1fr;
      }}
    }}

    @media (max-width: 720px) {{
      .page {{
        width: min(100vw - 16px, 1400px);
        padding: 16px 0 28px;
      }}

      .hero,
      .toolbar-left,
      .result-summary,
      .category-card {{
        border-radius: 18px;
      }}

      .hero {{
        padding: 20px;
      }}

      .hero h1 {{
        max-width: none;
        font-size: clamp(32px, 12vw, 48px);
      }}

      .stats-grid {{
        grid-template-columns: 1fr 1fr;
      }}

      .grid {{
        grid-template-columns: 1fr;
      }}
    }}
  </style>
</head>
<body>
  <main class="page">
    <section class="hero">
      <div class="hero-copy">
        <span class="hero-eyebrow">Developer Launchpad</span>
        <h1>开发者导航，快、清楚、可直接开干。</h1>
        <p>把收藏夹变成像样的开发者导航页。常用资源、工具站、社区和文档集中展示，支持搜索和快速筛选，点开就走。</p>
        <div class="hero-meta">
          <span class="meta-pill">source: {source_label}</span>
          <span class="meta-pill">generated: {generated_at}</span>
        </div>
      </div>
      <div class="hero-panel">
        <div class="stats-card">
          <small>available links</small>
          <strong>{len(rows)}</strong>
          <small>ready to open</small>
        </div>
        <div class="stats-grid">
          <div class="stat-box">
            <span>categories</span>
            <strong>{total_categories}</strong>
          </div>
          <div class="stat-box">
            <span>top groups</span>
            <strong>{len(top_categories)}</strong>
          </div>
        </div>
      </div>
    </section>

    <section class="toolbar">
      <div class="toolbar-left">
        <div class="toolbar-title">Search And Quick Filters</div>
        <div class="search-shell">
          <span class="search-icon">/</span>
          <input id="searchBox" class="search-box" type="search" placeholder="搜标题、域名、分类，比如：掘金 / 微信 / AI / swagger" />
        </div>
        <div class="chip-row">
          {chips}
        </div>
      </div>
      <div id="resultSummary" class="result-summary">
        <div>
          <strong>{len(rows)}</strong>
          <span>当前展示链接</span>
        </div>
        <div>覆盖 {total_categories} 个分类</div>
      </div>
    </section>

    <section id="categoryGrid" class="grid">
      {''.join(cards)}
    </section>

    <section id="emptyState" class="empty-state">
      没找到匹配结果，换个关键词试试。
    </section>
  </main>

  <script>
    const searchBox = document.getElementById('searchBox');
    const resultSummary = document.getElementById('resultSummary');
    const emptyState = document.getElementById('emptyState');
    const cards = [...document.querySelectorAll('.category-card')];
    const chips = [...document.querySelectorAll('.filter-chip')];
    let activeChip = '';

    function updateFilter() {{
      const query = searchBox.value.trim().toLowerCase();
      let visibleLinks = 0;
      let visibleCards = 0;

      cards.forEach((card) => {{
        const category = card.dataset.category || '';
        const items = [...card.querySelectorAll('.bookmark-item')];
        let cardVisibleCount = 0;

        items.forEach((item) => {{
          const title = item.dataset.title || '';
          const domain = item.dataset.domain || '';
          const matchesQuery = !query || title.includes(query) || domain.includes(query) || category.includes(query);
          const matchesChip = !activeChip || category.includes(activeChip);
          const matched = matchesQuery && matchesChip;
          item.style.display = matched ? '' : 'none';
          if (matched) {{
            cardVisibleCount += 1;
          }}
        }});

        const badge = card.querySelector('.category-count');
        badge.textContent = `${{cardVisibleCount}} 个链接`;
        card.style.display = cardVisibleCount ? '' : 'none';

        if (cardVisibleCount) {{
          visibleCards += 1;
          visibleLinks += cardVisibleCount;
        }}
      }});

      emptyState.classList.toggle('visible', visibleLinks === 0);
      resultSummary.innerHTML = `
        <div>
          <strong>${{visibleLinks}}</strong>
          <span>${{query || activeChip ? '筛选结果' : '当前展示链接'}}</span>
        </div>
        <div>分布在 ${{visibleCards}} 个分类</div>
      `;
    }}

    searchBox.addEventListener('input', updateFilter);
    chips.forEach((chip) => {{
      chip.addEventListener('click', () => {{
        const selected = chip.dataset.chip || '';
        activeChip = activeChip === selected ? '' : selected;
        chips.forEach((item) => item.classList.toggle('active', item.dataset.chip === activeChip));
        updateFilter();
      }});
    }});
  </script>
</body>
</html>
"""


def render_spotlight_html(rows: list[dict], source_name: str) -> str:
    ai_relay_mode = "ai中转站" in source_name.lower()

    def classify_resource(row: dict) -> str:
        combined = f"{row['title']} {row['url']} {row['domain']}".lower()
        path = urlparse(row["url"]).path.lower()
        fingerprint = row.get("fingerprint", {})
        platform = fingerprint.get("platform")

        if ai_relay_mode:
            if platform in {"深度识别为 NewAPI", "深度识别为 Sub2API", "待人工确认", "探测失败", "未识别"}:
                return platform
            if "sub2" in combined:
                return "明确是 Sub2"
            if any(token in combined for token in ("newapi", "new api")):
                return "明确是 NewAPI"
            if any(token in path for token in ("/subscriptions", "/purchase", "/workspace", "/usage", "/affiliate")):
                return "疑似 Sub2"
            if any(token in path for token in ("/keys", "/console", "/token", "/playground", "/dashboard", "/panel", "/topup", "/api-keys")):
                return "疑似 NewAPI"
            if any(token in combined for token in ("docs", "文档", "doc", "wiki", "教程", "github", "discord", "社区", "blog", "csdn", "掘金", "feishu")):
                return "文档社区"
            return "其他站点"

        if any(token in combined for token in ("docs", "文档", "doc", "wiki", "教程")):
            return "文档教程"
        if any(token in combined for token in ("充值", "订阅", "purchase", "shop", "topup", "redeem", "pricing")):
            return "购买充值"
        if any(token in combined for token in ("dashboard", "console", "keys", "monitor", "token", "profile", "subscriptions")):
            return "控制台"
        if any(token in combined for token in ("discord", "github", "社区", "forum", "blog", "csdn", "掘金", "feishu")):
            return "社区资讯"
        return "站点资源"

    buckets: OrderedDict[str, list[dict]] = OrderedDict()
    for row in rows:
        buckets.setdefault(classify_resource(row), []).append(row)

    favorite_section = ""
    sections: list[str] = []
    for label, items in buckets.items():
        entries = []
        for row in sorted(items, key=lambda item: item["title"].lower()):
            title = html.escape(row["title"])
            url = html.escape(row["url"], quote=True)
            domain = html.escape(row["domain"] or "未知来源")
            fingerprint = row.get("fingerprint", {})
            reason_text = html.escape(" | ".join(fingerprint.get("reasons", [])[:3])) if fingerprint.get("reasons") else ""
            entries.append(
                f"""
                <a class="resource-card" href="{url}" target="_blank" rel="noopener noreferrer">
                  <div class="resource-top">
                    <span class="resource-domain">{domain}</span>
                    <span class="resource-open">Open</span>
                  </div>
                  <strong>{title}</strong>
                  <span class="resource-url">{url}</span>
                  {f'<span class="resource-reason">{reason_text}</span>' if reason_text else ''}
                </a>
                """.strip()
            )

        sections.append(
            f"""
            <section class="resource-section" data-group="{html.escape(label.lower())}">
              <div class="section-head">
                <h2>{html.escape(label)}</h2>
                <span>{len(items)} 个链接</span>
              </div>
              <div class="resource-grid">
                {''.join(entries)}
              </div>
            </section>
            """.strip()
        )

    source_label = html.escape(source_name)
    generated_at = html.escape(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    domain_count = len({row["domain"] for row in rows})
    primary_chip = "".join(
        f'<button class="quick-chip" type="button" data-chip="{html.escape(label.lower())}">{html.escape(label)} <span>{len(items)}</span></button>'
        for label, items in buckets.items()
    )

    page_title = "AI 中转站来源识别面板" if ai_relay_mode else "AI 中转站资源总控台"
    page_desc = (
        "把 `ai中转站` 里的链接按 NewAPI / Sub2API 的站点指纹做识别。能确认的直接归类，确认不是这两类的单独剥离，剩下的再继续复核。"
        if ai_relay_mode
        else "把 `ai中转站` 里的全部链接集中成一个更舒服的专题页。按用途拆分、支持搜索，适合你这种链接很多、经常来回切换的使用方式。"
    )
    hint_pill = (
        '<span class="meta-pill">rule: 公开接口 + 标题 + 页面文案 + 人工复核覆盖</span>'
        if ai_relay_mode
        else ""
    )

    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>{page_title}</title>
  <style>
    :root {{
      --bg: #09111e;
      --bg-2: #0c1627;
      --panel: rgba(11, 19, 34, 0.88);
      --panel-soft: rgba(13, 24, 41, 0.76);
      --line: rgba(148, 163, 184, 0.14);
      --line-strong: rgba(56, 189, 248, 0.28);
      --text: #edf5ff;
      --muted: #8ba3c7;
      --accent: #38bdf8;
      --accent-2: #2dd4bf;
      --accent-3: #818cf8;
      --chip: rgba(56, 189, 248, 0.12);
      --shadow: 0 28px 70px rgba(2, 8, 23, 0.46);
      --mono: "Cascadia Code", "JetBrains Mono", "Fira Code", Consolas, monospace;
      --sans: "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif;
    }}

    * {{
      box-sizing: border-box;
    }}

    html {{
      color-scheme: dark;
    }}

    body {{
      margin: 0;
      font-family: var(--sans);
      color: var(--text);
      background:
        radial-gradient(circle at 8% 8%, rgba(56, 189, 248, 0.14), transparent 18%),
        radial-gradient(circle at 92% 12%, rgba(45, 212, 191, 0.14), transparent 20%),
        linear-gradient(180deg, #07101b 0%, #09111e 46%, #08111d 100%);
      min-height: 100vh;
    }}

    body::before {{
      content: "";
      position: fixed;
      inset: 0;
      pointer-events: none;
      background-image:
        linear-gradient(rgba(148, 163, 184, 0.05) 1px, transparent 1px),
        linear-gradient(90deg, rgba(148, 163, 184, 0.05) 1px, transparent 1px);
      background-size: 30px 30px;
      mask-image: linear-gradient(180deg, rgba(0,0,0,0.82), transparent 94%);
    }}

    .page {{
      width: min(1460px, calc(100vw - 24px));
      margin: 0 auto;
      padding: 22px 0 42px;
    }}

    .masthead {{
      display: grid;
      grid-template-columns: minmax(0, 1.2fr) minmax(260px, 0.8fr);
      gap: 18px;
      padding: 26px;
      border-radius: 24px;
      background: linear-gradient(180deg, rgba(10, 18, 33, 0.95), rgba(10, 18, 33, 0.82));
      border: 1px solid var(--line);
      box-shadow: var(--shadow);
    }}

    .eyebrow {{
      display: inline-flex;
      align-items: center;
      gap: 10px;
      padding: 8px 12px;
      border-radius: 999px;
      background: rgba(56, 189, 248, 0.09);
      border: 1px solid rgba(56, 189, 248, 0.22);
      color: var(--accent);
      font-family: var(--mono);
      font-size: 12px;
      letter-spacing: 0.08em;
      text-transform: uppercase;
    }}

    .masthead h1 {{
      margin: 14px 0 0;
      font-size: clamp(34px, 5vw, 58px);
      line-height: 0.96;
      letter-spacing: -0.04em;
      max-width: 10ch;
    }}

    .masthead p {{
      margin: 14px 0 0;
      max-width: 720px;
      color: var(--muted);
      line-height: 1.75;
      font-size: 16px;
    }}

    .meta-row {{
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      margin-top: 18px;
    }}

    .meta-pill {{
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 9px 12px;
      border-radius: 999px;
      background: rgba(148, 163, 184, 0.08);
      border: 1px solid rgba(148, 163, 184, 0.14);
      color: var(--muted);
      font-size: 13px;
      font-family: var(--mono);
    }}

    .summary-panel {{
      display: grid;
      gap: 12px;
      align-content: start;
    }}

    .big-stat {{
      padding: 18px;
      border-radius: 18px;
      background: linear-gradient(135deg, rgba(16, 28, 48, 0.98), rgba(8, 15, 27, 0.96));
      border: 1px solid var(--line-strong);
    }}

    .big-stat span,
    .mini-stat span {{
      display: block;
      color: var(--muted);
      font-family: var(--mono);
      font-size: 11px;
      letter-spacing: 0.08em;
      text-transform: uppercase;
    }}

    .big-stat strong {{
      display: block;
      margin: 10px 0 6px;
      font-size: clamp(34px, 4vw, 48px);
      line-height: 1;
    }}

    .mini-grid {{
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 12px;
    }}

    .mini-stat {{
      padding: 16px;
      border-radius: 18px;
      background: rgba(13, 24, 41, 0.82);
      border: 1px solid var(--line);
    }}

    .mini-stat strong {{
      display: block;
      margin-top: 8px;
      font-size: 24px;
      line-height: 1;
    }}

    .control-bar {{
      display: grid;
      grid-template-columns: minmax(0, 1fr) 250px;
      gap: 18px;
      margin: 20px 0;
    }}

    .search-panel,
    .status-panel {{
      border-radius: 22px;
      background: var(--panel);
      border: 1px solid var(--line);
      box-shadow: var(--shadow);
    }}

    .search-panel {{
      padding: 18px;
      display: grid;
      gap: 14px;
    }}

    .section-label {{
      color: var(--muted);
      font-family: var(--mono);
      font-size: 12px;
      letter-spacing: 0.08em;
      text-transform: uppercase;
    }}

    .search-box-wrap {{
      display: flex;
      align-items: center;
      gap: 12px;
      padding: 14px 16px;
      border-radius: 18px;
      background: rgba(7, 12, 22, 0.44);
      border: 1px solid rgba(148, 163, 184, 0.12);
    }}

    .search-box-wrap span {{
      width: 34px;
      height: 34px;
      border-radius: 12px;
      display: inline-grid;
      place-items: center;
      background: rgba(56, 189, 248, 0.14);
      color: var(--accent);
      font-family: var(--mono);
      font-size: 14px;
    }}

    .search-box {{
      width: 100%;
      border: 0;
      padding: 0;
      background: transparent;
      color: var(--text);
      font-size: 15px;
      outline: none;
    }}

    .search-box::placeholder {{
      color: #6f86ab;
    }}

    .chip-row {{
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
    }}

    .quick-chip {{
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 9px 12px;
      border-radius: 999px;
      background: var(--chip);
      border: 1px solid rgba(56, 189, 248, 0.16);
      color: #c6dbf6;
      font-family: var(--mono);
      font-size: 12px;
      cursor: pointer;
      transition: transform 0.15s ease, border-color 0.15s ease, background 0.15s ease;
    }}

    .quick-chip span {{
      color: var(--accent);
    }}

    .quick-chip:hover,
    .quick-chip.active {{
      transform: translateY(-1px);
      border-color: rgba(45, 212, 191, 0.3);
      background: rgba(45, 212, 191, 0.12);
    }}

    .status-panel {{
      padding: 18px;
      display: grid;
      gap: 8px;
      align-content: center;
    }}

    .status-panel strong {{
      display: block;
      font-size: 30px;
      line-height: 1;
    }}

    .status-panel span,
    .status-panel div:last-child {{
      color: var(--muted);
      font-size: 14px;
    }}

    .stack {{
      display: grid;
      gap: 18px;
    }}

    .resource-section {{
      padding: 18px;
      border-radius: 22px;
      background: var(--panel-soft);
      border: 1px solid var(--line);
      box-shadow: var(--shadow);
    }}

    .section-head {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      margin-bottom: 16px;
    }}

    .section-head h2 {{
      margin: 0;
      font-size: 24px;
      letter-spacing: -0.02em;
    }}

    .section-head span {{
      padding: 8px 10px;
      border-radius: 999px;
      background: rgba(129, 140, 248, 0.12);
      color: #c7d2fe;
      font-family: var(--mono);
      font-size: 12px;
      white-space: nowrap;
    }}

    .resource-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      gap: 12px;
    }}

    .resource-card {{
      display: block;
      padding: 14px;
      border-radius: 18px;
      text-decoration: none;
      color: var(--text);
      background: rgba(8, 14, 24, 0.4);
      border: 1px solid rgba(148, 163, 184, 0.08);
      transition: transform 0.15s ease, border-color 0.15s ease, background 0.15s ease;
    }}

    .resource-card:hover {{
      transform: translateY(-1px);
      border-color: rgba(56, 189, 248, 0.22);
      background: rgba(10, 18, 32, 0.78);
    }}

    .resource-top {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
      margin-bottom: 12px;
    }}

    .resource-domain {{
      color: var(--accent);
      font-family: var(--mono);
      font-size: 11px;
      word-break: break-all;
    }}

    .resource-open {{
      color: var(--muted);
      font-family: var(--mono);
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.08em;
    }}

    .resource-card strong {{
      display: block;
      font-size: 15px;
      line-height: 1.5;
      margin-bottom: 10px;
      word-break: break-word;
    }}

    .resource-url {{
      display: block;
      color: var(--muted);
      font-family: var(--mono);
      font-size: 11px;
      line-height: 1.55;
      word-break: break-all;
    }}

    .resource-reason {{
      display: block;
      margin-top: 10px;
      color: #6fd7c7;
      font-family: var(--mono);
      font-size: 10px;
      line-height: 1.5;
      word-break: break-all;
    }}

    .empty-state {{
      display: none;
      padding: 26px;
      border-radius: 22px;
      border: 1px dashed rgba(148, 163, 184, 0.22);
      background: var(--panel);
      color: var(--muted);
      text-align: center;
      box-shadow: var(--shadow);
    }}

    .empty-state.visible {{
      display: block;
    }}

    @media (max-width: 980px) {{
      .masthead,
      .control-bar {{
        grid-template-columns: 1fr;
      }}
    }}

    @media (max-width: 720px) {{
      .page {{
        width: min(100vw - 14px, 1460px);
        padding: 14px 0 28px;
      }}

      .masthead,
      .search-panel,
      .status-panel,
      .resource-section {{
        border-radius: 18px;
      }}

      .masthead {{
        padding: 20px;
      }}

      .masthead h1 {{
        max-width: none;
        font-size: clamp(32px, 11vw, 46px);
      }}

      .resource-grid {{
        grid-template-columns: 1fr;
      }}
    }}
  </style>
</head>
<body>
  <main class="page">
    <section class="masthead">
      <div>
        <span class="eyebrow">AI Relay Hub</span>
        <h1>{page_title}</h1>
        <p>{page_desc}</p>
        <div class="meta-row">
          <span class="meta-pill">source: {source_label}</span>
          <span class="meta-pill">generated: {generated_at}</span>
          {hint_pill}
        </div>
      </div>
      <div class="summary-panel">
        <div class="big-stat">
          <span>resource count</span>
          <strong>{len(rows)}</strong>
          <span>links collected</span>
        </div>
        <div class="mini-grid">
          <div class="mini-stat">
            <span>groups</span>
            <strong>{len(buckets)}</strong>
          </div>
          <div class="mini-stat">
            <span>domains</span>
            <strong>{domain_count}</strong>
          </div>
        </div>
      </div>
    </section>

    <section class="control-bar">
      <div class="search-panel">
        <div class="section-label">Search And Focus</div>
        <div class="search-box-wrap">
          <span>/</span>
          <input id="searchBox" class="search-box" type="search" placeholder="搜标题、域名、用途，比如：docs / token / dashboard / 充值" />
        </div>
        <div class="chip-row">
          {primary_chip}
        </div>
      </div>
      <div id="statusPanel" class="status-panel">
        <div>
          <strong>{len(rows)}</strong>
          <span>当前展示链接</span>
        </div>
        <div>分布在 {len(buckets)} 个分组</div>
      </div>
    </section>

    <section id="sectionStack" class="stack">
      {''.join(sections)}
    </section>

    <section id="emptyState" class="empty-state">
      没找到匹配结果，换个关键词试试。
    </section>
  </main>

  <script>
    const searchBox = document.getElementById('searchBox');
    const statusPanel = document.getElementById('statusPanel');
    const emptyState = document.getElementById('emptyState');
    const sections = [...document.querySelectorAll('.resource-section')];
    const chips = [...document.querySelectorAll('.quick-chip')];
    let activeChip = '';

    function updateView() {{
      const query = searchBox.value.trim().toLowerCase();
      let visibleLinks = 0;
      let visibleSections = 0;

      sections.forEach((section) => {{
        const group = section.dataset.group || '';
        const cards = [...section.querySelectorAll('.resource-card')];
        let visibleInSection = 0;

        cards.forEach((card) => {{
          const combined = card.innerText.toLowerCase();
          const matchesQuery = !query || combined.includes(query);
          const matchesChip = !activeChip || group.includes(activeChip);
          const visible = matchesQuery && matchesChip;
          card.style.display = visible ? '' : 'none';
          if (visible) visibleInSection += 1;
        }});

        section.style.display = visibleInSection ? '' : 'none';
        const badge = section.querySelector('.section-head span');
        badge.textContent = `${{visibleInSection}} 个链接`;
        if (visibleInSection) {{
          visibleLinks += visibleInSection;
          visibleSections += 1;
        }}
      }});

      emptyState.classList.toggle('visible', visibleLinks === 0);
      statusPanel.innerHTML = `
        <div>
          <strong>${{visibleLinks}}</strong>
          <span>${{query || activeChip ? '筛选结果' : '当前展示链接'}}</span>
        </div>
        <div>分布在 ${{visibleSections}} 个分组</div>
      `;
    }}

    searchBox.addEventListener('input', updateView);
    chips.forEach((chip) => {{
      chip.addEventListener('click', () => {{
        const value = chip.dataset.chip || '';
        activeChip = activeChip === value ? '' : value;
        chips.forEach((item) => item.classList.toggle('active', item.dataset.chip === activeChip));
        updateView();
      }});
    }});
  </script>
</body>
</html>
"""


def export_html(bookmarks_data: dict, output_path: Path) -> Path:
    rows = flatten_children(bookmarks_data["roots"]["bookmark_bar"].get("children", []))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    html_content = render_bookmarks_html(rows, "Chrome 书签栏")
    output_path.write_text(html_content, encoding="utf-8")
    return output_path


def render_spotlight_html(rows: list[dict], source_name: str) -> str:
    lower_source_name = source_name.lower()
    ai_relay_mode = "ai" in lower_source_name and any(token in source_name for token in ("中转", "社区"))

    platform_group_order = [
        "我的常用",
        "深度识别为 NewAPI",
        "深度识别为 Sub2API",
        "公益站",
        "比价站",
        "非这两类",
        "待人工确认",
        "探测失败",
    ]
    platform_group_meta = {
        "我的常用": "你平时高频打开的站点，固定置顶，优先给你最快找到。",
        "深度识别为 NewAPI": "命中 NewAPI 公开接口或前端强指纹，优先可直接用。",
        "深度识别为 Sub2API": "命中 Sub2API 公开接口或前端强指纹，优先可直接筛。",
        "公益站": "这类站点更偏向签到、积分、白嫖额度或低门槛拿量，适合单独观察。",
        "比价站": "这类站点更适合拿来横向对比套餐、模型和价格，不一定是最终使用入口。",
        "非这两类": "已人工排除或明显属于其他自建/信息站，不再混进目标池。",
        "待人工确认": "有少量特征，但还不够稳，适合你二次扫一遍。",
        "探测失败": "当前无法完成探测，可能是站点挂了、拦截了请求，或首页太干净。",
    }
    legacy_platform_map = {
        "明确是 NewAPI": "深度识别为 NewAPI",
        "明确是 Sub2": "深度识别为 Sub2API",
        "疑似 NewAPI": "待人工确认",
        "疑似 Sub2": "待人工确认",
        "其他站点": "非这两类",
        "文档社区": "非这两类",
        "未识别": "待人工确认",
    }
    general_group_order = ["文档教程", "购买充值", "控制台", "社区资讯", "站点资源"]

    def normalize_platform_label(platform: str | None) -> str | None:
        if not platform:
            return None
        return legacy_platform_map.get(platform, platform)

    def format_reason(reason: str) -> str:
        if reason.startswith("api:newapi-status"):
            return "命中公开接口 /api/status"
        if reason.startswith("api:sub2api-public-settings"):
            return "命中公开接口 /api/v1/settings/public"
        if reason.startswith("manual:"):
            return f"人工校正: {reason.split(':', 1)[1]}"
        if reason.startswith("title:"):
            return f"标题指纹: {reason.split(':', 1)[1]}"
        if reason.startswith("newapi:"):
            return f"NewAPI 标记: {reason.split(':', 1)[1]}"
        if reason.startswith("sub2:"):
            return f"Sub2API 标记: {reason.split(':', 1)[1]}"
        if reason.startswith("newapi-path:"):
            return f"NewAPI 路径: {reason.split(':', 1)[1]}"
        if reason.startswith("sub2-path:"):
            return f"Sub2API 路径: {reason.split(':', 1)[1]}"
        if reason == "newapi-domain":
            return "域名中包含 newapi"
        if reason == "sub2-domain":
            return "域名中包含 sub2"
        return reason

    def badge_class(label: str) -> str:
        if label == "我的常用":
            return "is-favorite"
        if "NewAPI" in label:
            return "is-newapi"
        if "Sub2API" in label or "Sub2" in label:
            return "is-sub2"
        if label == "公益站":
            return "is-review"
        if label == "比价站":
            return "is-other"
        if label == "非这两类":
            return "is-other"
        if label == "待人工确认":
            return "is-review"
        return "is-failed"

    def assessment_badge_html(row: dict) -> str:
        assessment = row.get("assessment") or {}
        if not assessment:
            return ""
        trust_label = html.escape(str(assessment.get("trust_label", "")))
        trust_class = html.escape(str(assessment.get("trust_class", "")))
        risk_label = html.escape(str(assessment.get("risk_label", "")))
        entry_type = html.escape(str(assessment.get("entry_type", "")))
        trust_score = int(assessment.get("trust_score", 0) or 0)
        return (
            f'<span class="assessment-chip {trust_class}">{trust_label} {trust_score}</span>'
            f'<span class="assessment-chip is-entry">{entry_type}</span>'
            f'<span class="assessment-chip is-risk">{risk_label}</span>'
        )

    def classify_resource(row: dict) -> str:
        combined = f"{row['title']} {row['url']} {row['domain']}".lower()
        path = urlparse(row["url"]).path.lower()
        fingerprint = row.get("fingerprint", {})
        platform = normalize_platform_label(fingerprint.get("platform"))

        if ai_relay_mode:
            if is_pinned_domain(row.get("domain", "")):
                return "我的常用"
            if is_public_benefit_row(row):
                return "公益站"
            if is_price_comparison_row(row):
                return "比价站"
            if platform in platform_group_meta:
                return platform
            if any(
                token in combined
                for token in ("docs", "doc", "wiki", "github", "discord", "blog", "forum", "csdn", "feishu")
            ):
                return "非这两类"
            if "sub2" in combined and "newapi" not in combined:
                return "待人工确认"
            if any(token in path for token in ("/subscriptions", "/purchase", "/workspace", "/usage", "/affiliate")):
                return "待人工确认"
            if any(token in combined for token in ("newapi", "new api")):
                return "待人工确认"
            if any(token in path for token in ("/keys", "/console", "/token", "/playground", "/dashboard", "/panel", "/topup", "/api-keys")):
                return "待人工确认"
            return "探测失败"

        if any(token in combined for token in ("docs", "doc", "wiki")):
            return "文档教程"
        if any(token in combined for token in ("purchase", "shop", "topup", "redeem", "pricing")):
            return "购买充值"
        if any(token in combined for token in ("dashboard", "console", "keys", "monitor", "token", "profile", "subscriptions")):
            return "控制台"
        if any(token in combined for token in ("discord", "github", "forum", "blog", "csdn", "feishu")):
            return "社区资讯"
        return "站点资源"

    grouped_buckets: dict[str, list[dict]] = {}
    for row in rows:
        grouped_buckets.setdefault(classify_resource(row), []).append(row)

    ordered_labels = platform_group_order if ai_relay_mode else general_group_order
    trailing_labels = [label for label in grouped_buckets if label not in ordered_labels]
    buckets: OrderedDict[str, list[dict]] = OrderedDict(
        (label, grouped_buckets[label])
        for label in [*ordered_labels, *trailing_labels]
        if label in grouped_buckets
    )

    sections: list[str] = []
    for label, items in buckets.items():
        entries = []
        for row in sorted(items, key=lambda item: item["title"].lower()):
            title = html.escape(row["title"])
            url = html.escape(row["url"], quote=True)
            domain = html.escape(row["domain"] or "未知来源")
            fingerprint = row.get("fingerprint", {})
            score = fingerprint.get("score", 0)
            reason_list = [format_reason(str(reason)) for reason in fingerprint.get("reasons", [])[:4]]
            reason_text = html.escape(" | ".join(reason_list)) if reason_list else ""
            meta_html = ""
            if ai_relay_mode:
                score_html = f'<span class="resource-score">score {int(score)}</span>' if score else ""
                assessment_html = assessment_badge_html(row)
                meta_html = (
                    f'<div class="resource-meta">'
                    f'<span class="platform-badge {badge_class(label)}">{html.escape(label)}</span>'
                    f"{score_html}"
                    f"{assessment_html}"
                    f"</div>"
                )
            entries.append(
                f"""
                <a class="resource-card" href="{url}" target="_blank" rel="noopener noreferrer">
                  <div class="resource-top">
                    <span class="resource-domain">{domain}</span>
                    <span class="resource-open">Open</span>
                  </div>
                  {meta_html}
                  <strong>{title}</strong>
                  <span class="resource-url">{url}</span>
                  {f'<span class="resource-reason">{reason_text}</span>' if reason_text else ''}
                </a>
                """.strip()
            )

        section_hint = platform_group_meta.get(label, "") if ai_relay_mode else ""
        section_html = f"""
        <section class="resource-section" data-group="{html.escape(label.lower())}">
          <div class="section-head">
            <div class="section-copy">
              <h2>{html.escape(label)}</h2>
              {f'<p>{html.escape(section_hint)}</p>' if section_hint else ''}
            </div>
            <span>{len(items)} 个链接</span>
          </div>
          <div class="resource-grid">
            {''.join(entries)}
          </div>
        </section>
        """.strip()

        if label == "我的常用":
            feature_cards = []
            for row in sorted(items, key=lambda item: item["title"].lower()):
                title = html.escape(row["title"])
                url = html.escape(row["url"], quote=True)
                domain = html.escape(row["domain"] or "未知来源")
                assessment = row.get("assessment") or {}
                trust_score = int(assessment.get("trust_score", 0) or 0)
                feature_cards.append(
                    f"""
                    <a class="favorite-hero-card" href="{url}" target="_blank" rel="noopener noreferrer">
                      <div class="favorite-hero-card__orb"></div>
                      <div class="favorite-hero-card__top">
                        <span class="favorite-hero-card__domain">{domain}</span>
                        <span class="favorite-hero-card__open">Launch</span>
                      </div>
                      <strong>{title}</strong>
                      <div class="favorite-hero-card__meta">
                        <span>常用站</span>
                        <span>可信 {trust_score}</span>
                      </div>
                    </a>
                    """.strip()
                )
            favorite_section = f"""
            <section class="favorite-hero" aria-label="我的常用快捷区">
              <div class="favorite-hero__copy">
                <span class="favorite-hero__eyebrow">Priority Deck</span>
                <h2>我的常用</h2>
                <p>把你最常开的 4 个站抬到最上面，做成一眼就能点开的专属快捷区。</p>
              </div>
              <div class="favorite-hero__grid">
                {''.join(feature_cards)}
              </div>
            </section>
            {section_html}
            """.strip()
        else:
            sections.append(section_html)

    source_label = html.escape(source_name)
    generated_at = html.escape(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    domain_count = len({row["domain"] for row in rows})
    primary_chip = "".join(
        f'<button class="quick-chip" type="button" data-chip="{html.escape(label.lower())}">{html.escape(label)} <span>{len(items)}</span></button>'
        for label, items in buckets.items()
    )

    page_title = "AI 中转站站点识别面板" if ai_relay_mode else "AI 中转站资源总览"
    page_desc = (
        "把 ai中转站 里的全部链接按 NewAPI / Sub2API 深度识别结果收拢展示，保留识别依据和分数，方便你快速筛站。"
        if ai_relay_mode
        else "把这个文件夹里的链接做成一个更顺手的导航页，支持搜索、筛选和快速打开。"
    )
    hint_pill = (
        '<span class="meta-pill">rule: 公开接口 + 页面标题 + 前端指纹 + 人工校正</span>'
        if ai_relay_mode
        else ""
    )

    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>{page_title}</title>
  <style>
    :root {{
      --bg: #071019;
      --bg-2: #0c1522;
      --panel: rgba(10, 17, 28, 0.88);
      --panel-soft: rgba(12, 21, 34, 0.78);
      --line: rgba(120, 144, 170, 0.14);
      --line-strong: rgba(59, 130, 246, 0.24);
      --text: #eef4fb;
      --muted: #8aa0ba;
      --accent: #4ea1ff;
      --accent-2: #2dd4bf;
      --accent-3: #f59e0b;
      --danger: #fb7185;
      --other: #94a3b8;
      --shadow: 0 28px 70px rgba(2, 8, 20, 0.46);
      --mono: "Cascadia Code", "JetBrains Mono", "Fira Code", Consolas, monospace;
      --sans: "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif;
    }}

    * {{
      box-sizing: border-box;
    }}

    html {{
      color-scheme: dark;
    }}

    body {{
      margin: 0;
      font-family: var(--sans);
      color: var(--text);
      background:
        radial-gradient(circle at 8% 10%, rgba(78, 161, 255, 0.16), transparent 20%),
        radial-gradient(circle at 92% 12%, rgba(45, 212, 191, 0.11), transparent 20%),
        linear-gradient(180deg, #060d16 0%, #09111b 44%, #08111a 100%);
      min-height: 100vh;
    }}

    body::before {{
      content: "";
      position: fixed;
      inset: 0;
      pointer-events: none;
      background-image:
        linear-gradient(rgba(148, 163, 184, 0.04) 1px, transparent 1px),
        linear-gradient(90deg, rgba(148, 163, 184, 0.04) 1px, transparent 1px);
      background-size: 30px 30px;
      mask-image: linear-gradient(180deg, rgba(0,0,0,0.86), transparent 95%);
    }}

    .page {{
      width: min(1480px, calc(100vw - 24px));
      margin: 0 auto;
      padding: 20px 0 40px;
    }}

    .masthead {{
      display: grid;
      grid-template-columns: minmax(0, 1.45fr) 330px;
      gap: 18px;
      padding: 24px;
      border-radius: 26px;
      background: linear-gradient(180deg, rgba(10, 18, 32, 0.95), rgba(10, 18, 32, 0.82));
      border: 1px solid var(--line);
      box-shadow: var(--shadow);
    }}

    .eyebrow {{
      display: inline-flex;
      align-items: center;
      gap: 10px;
      padding: 8px 12px;
      border-radius: 999px;
      background: rgba(78, 161, 255, 0.1);
      border: 1px solid rgba(78, 161, 255, 0.22);
      color: var(--accent);
      font-family: var(--mono);
      font-size: 12px;
      letter-spacing: 0.08em;
      text-transform: uppercase;
    }}

    .masthead h1 {{
      margin: 14px 0 0;
      font-size: clamp(34px, 5vw, 56px);
      line-height: 0.96;
      letter-spacing: -0.04em;
      max-width: 10ch;
    }}

    .masthead p {{
      margin: 14px 0 0;
      max-width: 780px;
      color: var(--muted);
      line-height: 1.78;
      font-size: 16px;
    }}

    .meta-row {{
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      margin-top: 18px;
    }}

    .meta-pill {{
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 9px 12px;
      border-radius: 999px;
      background: rgba(148, 163, 184, 0.08);
      border: 1px solid rgba(148, 163, 184, 0.14);
      color: var(--muted);
      font-size: 13px;
      font-family: var(--mono);
    }}

    .summary-panel {{
      display: grid;
      gap: 12px;
      align-content: start;
    }}

    .big-stat {{
      padding: 18px;
      border-radius: 18px;
      background: linear-gradient(135deg, rgba(15, 27, 46, 0.98), rgba(8, 15, 27, 0.96));
      border: 1px solid var(--line-strong);
    }}

    .big-stat span,
    .mini-stat span {{
      display: block;
      color: var(--muted);
      font-family: var(--mono);
      font-size: 11px;
      letter-spacing: 0.08em;
      text-transform: uppercase;
    }}

    .big-stat strong {{
      display: block;
      margin: 10px 0 6px;
      font-size: clamp(34px, 4vw, 48px);
      line-height: 1;
    }}

    .mini-grid {{
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 12px;
    }}

    .mini-stat {{
      padding: 16px;
      border-radius: 18px;
      background: rgba(13, 24, 41, 0.82);
      border: 1px solid var(--line);
    }}

    .mini-stat strong {{
      display: block;
      margin-top: 8px;
      font-size: 24px;
      line-height: 1;
    }}

    .control-bar {{
      display: grid;
      grid-template-columns: minmax(0, 1fr) 250px;
      gap: 18px;
      margin: 20px 0;
    }}

    .search-panel,
    .status-panel {{
      border-radius: 22px;
      background: var(--panel);
      border: 1px solid var(--line);
      box-shadow: var(--shadow);
    }}

    .search-panel {{
      padding: 18px;
      display: grid;
      gap: 14px;
    }}

    .section-label {{
      color: var(--muted);
      font-family: var(--mono);
      font-size: 12px;
      letter-spacing: 0.08em;
      text-transform: uppercase;
    }}

    .search-box-wrap {{
      display: flex;
      align-items: center;
      gap: 12px;
      padding: 14px 16px;
      border-radius: 18px;
      background: rgba(7, 12, 22, 0.44);
      border: 1px solid rgba(148, 163, 184, 0.12);
    }}

    .search-box-wrap span {{
      width: 34px;
      height: 34px;
      border-radius: 12px;
      display: inline-grid;
      place-items: center;
      background: rgba(78, 161, 255, 0.14);
      color: var(--accent);
      font-family: var(--mono);
      font-size: 14px;
    }}

    .search-box {{
      width: 100%;
      border: 0;
      outline: none;
      background: transparent;
      color: var(--text);
      font-size: 15px;
    }}

    .search-box::placeholder {{
      color: #6c86a6;
    }}

    .chip-row {{
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
    }}

    .quick-chip {{
      display: inline-flex;
      align-items: center;
      gap: 10px;
      padding: 10px 14px;
      border-radius: 999px;
      border: 1px solid rgba(148, 163, 184, 0.14);
      background: rgba(10, 18, 32, 0.76);
      color: var(--text);
      cursor: pointer;
      font-family: var(--mono);
      font-size: 12px;
      transition: 0.16s ease;
    }}

    .quick-chip span {{
      color: var(--muted);
    }}

    .quick-chip:hover,
    .quick-chip.active {{
      border-color: rgba(78, 161, 255, 0.34);
      background: rgba(78, 161, 255, 0.1);
      color: #d9eaff;
    }}

    .status-panel {{
      padding: 18px;
      display: grid;
      align-content: center;
      gap: 10px;
    }}

    .status-panel strong {{
      display: block;
      font-size: 34px;
      line-height: 1;
    }}

    .status-panel span,
    .status-panel div:last-child {{
      color: var(--muted);
      font-size: 13px;
    }}

    .stack {{
      display: grid;
      gap: 16px;
    }}

    .resource-section {{
      padding: 20px;
      border-radius: 22px;
      background: var(--panel-soft);
      border: 1px solid var(--line);
      box-shadow: var(--shadow);
    }}

    .section-head {{
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 12px;
      margin-bottom: 16px;
    }}

    .section-copy h2 {{
      margin: 0;
      font-size: 24px;
      letter-spacing: -0.02em;
    }}

    .section-copy p {{
      margin: 8px 0 0;
      color: var(--muted);
      font-size: 13px;
      line-height: 1.7;
      max-width: 720px;
    }}

    .section-head > span {{
      padding: 8px 10px;
      border-radius: 999px;
      background: rgba(129, 140, 248, 0.12);
      color: #c7d2fe;
      font-family: var(--mono);
      font-size: 12px;
      white-space: nowrap;
    }}

    .resource-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(295px, 1fr));
      gap: 12px;
    }}

    .resource-card {{
      display: block;
      padding: 16px;
      border-radius: 20px;
      text-decoration: none;
      color: var(--text);
      background:
        linear-gradient(180deg, rgba(10, 17, 29, 0.92), rgba(7, 13, 22, 0.86));
      border: 1px solid rgba(148, 163, 184, 0.08);
      transition: transform 0.16s ease, border-color 0.16s ease, background 0.16s ease, box-shadow 0.16s ease;
    }}

    .resource-card:hover {{
      transform: translateY(-2px);
      border-color: rgba(78, 161, 255, 0.22);
      background: linear-gradient(180deg, rgba(11, 20, 35, 0.98), rgba(8, 15, 26, 0.94));
      box-shadow: 0 18px 38px rgba(4, 10, 20, 0.32);
    }}

    .resource-top {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
      margin-bottom: 12px;
    }}

    .resource-domain {{
      color: var(--accent);
      font-family: var(--mono);
      font-size: 11px;
      word-break: break-all;
    }}

    .resource-open {{
      color: var(--muted);
      font-family: var(--mono);
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.08em;
    }}

    .resource-meta {{
      display: flex;
      align-items: center;
      flex-wrap: wrap;
      gap: 8px;
      margin-bottom: 12px;
    }}

    .platform-badge,
    .resource-score {{
      display: inline-flex;
      align-items: center;
      height: 26px;
      padding: 0 10px;
      border-radius: 999px;
      font-family: var(--mono);
      font-size: 11px;
      letter-spacing: 0.02em;
    }}

    .platform-badge {{
      border: 1px solid transparent;
    }}

    .platform-badge.is-newapi {{
      color: #dbeafe;
      background: rgba(59, 130, 246, 0.14);
      border-color: rgba(59, 130, 246, 0.24);
    }}

    .platform-badge.is-sub2 {{
      color: #ccfbf1;
      background: rgba(45, 212, 191, 0.14);
      border-color: rgba(45, 212, 191, 0.24);
    }}

    .platform-badge.is-other {{
      color: #e2e8f0;
      background: rgba(148, 163, 184, 0.12);
      border-color: rgba(148, 163, 184, 0.22);
    }}

    .platform-badge.is-review {{
      color: #fde68a;
      background: rgba(245, 158, 11, 0.12);
      border-color: rgba(245, 158, 11, 0.24);
    }}

    .platform-badge.is-failed {{
      color: #fecdd3;
      background: rgba(251, 113, 133, 0.12);
      border-color: rgba(251, 113, 133, 0.22);
    }}

    .resource-score {{
      color: var(--muted);
      background: rgba(148, 163, 184, 0.08);
      border: 1px solid rgba(148, 163, 184, 0.14);
    }}

    .resource-card strong {{
      display: block;
      font-size: 15px;
      line-height: 1.55;
      margin-bottom: 10px;
      word-break: break-word;
    }}

    .resource-url {{
      display: block;
      color: var(--muted);
      font-family: var(--mono);
      font-size: 11px;
      line-height: 1.6;
      word-break: break-all;
    }}

    .resource-reason {{
      display: block;
      margin-top: 12px;
      padding-top: 12px;
      border-top: 1px dashed rgba(148, 163, 184, 0.12);
      color: #7ee7d6;
      font-family: var(--mono);
      font-size: 10px;
      line-height: 1.7;
      word-break: break-all;
    }}

    .empty-state {{
      display: none;
      padding: 26px;
      border-radius: 22px;
      border: 1px dashed rgba(148, 163, 184, 0.22);
      background: var(--panel);
      color: var(--muted);
      text-align: center;
      box-shadow: var(--shadow);
    }}

    .empty-state.visible {{
      display: block;
    }}

    @media (max-width: 980px) {{
      .masthead,
      .control-bar {{
        grid-template-columns: 1fr;
      }}
    }}

    @media (max-width: 720px) {{
      .page {{
        width: min(100vw - 14px, 1480px);
        padding: 14px 0 28px;
      }}

      .masthead,
      .search-panel,
      .status-panel,
      .resource-section {{
        border-radius: 18px;
      }}

      .masthead {{
        padding: 20px;
      }}

      .masthead h1 {{
        max-width: none;
        font-size: clamp(32px, 11vw, 46px);
      }}

      .resource-grid {{
        grid-template-columns: 1fr;
      }}
    }}
  </style>
</head>
<body>
  <main class="page">
    <section class="masthead">
      <div>
        <span class="eyebrow">AI Relay Navigator</span>
        <h1>{page_title}</h1>
        <p>{page_desc}</p>
        <div class="meta-row">
          <span class="meta-pill">source: {source_label}</span>
          <span class="meta-pill">generated: {generated_at}</span>
          {hint_pill}
        </div>
      </div>
      <div class="summary-panel">
        <div class="big-stat">
          <span>resource count</span>
          <strong>{len(rows)}</strong>
          <span>links collected</span>
        </div>
        <div class="mini-grid">
          <div class="mini-stat">
            <span>groups</span>
            <strong>{len(buckets)}</strong>
          </div>
          <div class="mini-stat">
            <span>domains</span>
            <strong>{domain_count}</strong>
          </div>
        </div>
      </div>
    </section>

    <section class="control-bar">
      <div class="search-panel">
        <div class="section-label">Search And Focus</div>
        <div class="search-box-wrap">
          <span>/</span>
          <input id="searchBox" class="search-box" type="search" placeholder="搜标题、域名、指纹依据，比如 newapi / sub2 / dashboard / 公开接口" />
        </div>
        <div class="chip-row">
          {primary_chip}
        </div>
      </div>
      <div id="statusPanel" class="status-panel">
        <div>
          <strong>{len(rows)}</strong>
          <span>当前展示链接</span>
        </div>
        <div>分布在 {len(buckets)} 个分组</div>
      </div>
    </section>

    <section id="sectionStack" class="stack">
      {favorite_section}
      {''.join(sections)}
    </section>

    <section id="emptyState" class="empty-state">
      没找到匹配结果，换个关键词再试试。
    </section>
  </main>

  <script>
    const searchBox = document.getElementById('searchBox');
    const statusPanel = document.getElementById('statusPanel');
    const emptyState = document.getElementById('emptyState');
    const sections = [...document.querySelectorAll('.resource-section')];
    const chips = [...document.querySelectorAll('.quick-chip')];
    let activeChip = '';

    function updateView() {{
      const query = searchBox.value.trim().toLowerCase();
      let visibleLinks = 0;
      let visibleSections = 0;

      sections.forEach((section) => {{
        const group = section.dataset.group || '';
        const cards = [...section.querySelectorAll('.resource-card')];
        let visibleInSection = 0;

        cards.forEach((card) => {{
          const combined = card.innerText.toLowerCase();
          const matchesQuery = !query || combined.includes(query);
          const matchesChip = !activeChip || group.includes(activeChip);
          const visible = matchesQuery && matchesChip;
          card.style.display = visible ? '' : 'none';
          if (visible) visibleInSection += 1;
        }});

        section.style.display = visibleInSection ? '' : 'none';
        const badge = section.querySelector('.section-head > span');
        badge.textContent = `${{visibleInSection}} 个链接`;
        if (visibleInSection) {{
          visibleLinks += visibleInSection;
          visibleSections += 1;
        }}
      }});

      emptyState.classList.toggle('visible', visibleLinks === 0);
      statusPanel.innerHTML = `
        <div>
          <strong>${{visibleLinks}}</strong>
          <span>${{query || activeChip ? '筛选结果' : '当前展示链接'}}</span>
        </div>
        <div>分布在 ${{visibleSections}} 个分组</div>
      `;
    }}

    searchBox.addEventListener('input', updateView);
    chips.forEach((chip) => {{
      chip.addEventListener('click', () => {{
        const value = chip.dataset.chip || '';
        activeChip = activeChip === value ? '' : value;
        chips.forEach((item) => item.classList.toggle('active', item.dataset.chip === activeChip));
        updateView();
      }});
    }});
  </script>
</body>
</html>
"""
_legacy_spotlight_renderer = render_spotlight_html


def render_spotlight_html(rows: list[dict], source_name: str) -> str:
    html_doc = _legacy_spotlight_renderer(rows, source_name)
    dashboard_css = r"""
    :root {
      --bg: #f6f8fb;
      --surface: #ffffff;
      --surface-soft: #f9fbff;
      --surface-strong: #eef4ff;
      --text: #172033;
      --muted: #667085;
      --subtle: #8a95a8;
      --line: #d9e2ef;
      --line-strong: #b9c8dd;
      --primary: #1d4ed8;
      --primary-soft: #dbeafe;
      --newapi: #1d4ed8;
      --sub2: #047857;
      --other: #475569;
      --review: #a16207;
      --failed: #be123c;
      --shadow: 0 1px 2px rgba(15, 23, 42, 0.06);
      --mono: "Cascadia Code", "JetBrains Mono", "Fira Code", Consolas, monospace;
      --sans: "Segoe UI", "Microsoft YaHei", "PingFang SC", sans-serif;
    }

    * {
      box-sizing: border-box;
    }

    html {
      color-scheme: light;
      scroll-behavior: smooth;
    }

    body {
      margin: 0;
      min-height: 100vh;
      background:
        linear-gradient(90deg, rgba(29, 78, 216, 0.05) 1px, transparent 1px),
        linear-gradient(rgba(29, 78, 216, 0.04) 1px, transparent 1px),
        var(--bg);
      background-size: 32px 32px;
      color: var(--text);
      font-family: var(--sans);
      font-size: 15px;
      line-height: 1.5;
    }

    body::before {
      display: none;
    }

    .page {
      width: min(1560px, calc(100vw - 32px));
      margin: 0 auto;
      padding: 16px 0 40px;
    }

    .masthead {
      display: grid;
      grid-template-columns: minmax(0, 1fr) 360px;
      gap: 16px;
      padding: 20px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: rgba(255, 255, 255, 0.92);
      box-shadow: var(--shadow);
      backdrop-filter: blur(12px);
    }

    .eyebrow {
      display: inline-flex;
      align-items: center;
      min-height: 28px;
      padding: 0 10px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: var(--surface-soft);
      color: var(--primary);
      font-family: var(--mono);
      font-size: 12px;
      font-weight: 700;
      letter-spacing: 0;
      text-transform: uppercase;
    }

    .masthead h1 {
      margin: 12px 0 0;
      max-width: none;
      color: #111827;
      font-size: clamp(28px, 3vw, 42px);
      font-weight: 750;
      line-height: 1.12;
      letter-spacing: 0;
    }

    .masthead p {
      max-width: 820px;
      margin: 10px 0 0;
      color: var(--muted);
      font-size: 15px;
      line-height: 1.7;
    }

    .meta-row {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-top: 14px;
    }

    .meta-pill {
      display: inline-flex;
      align-items: center;
      min-height: 30px;
      padding: 0 10px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: var(--surface-soft);
      color: var(--muted);
      font-family: var(--mono);
      font-size: 12px;
      letter-spacing: 0;
    }

    .summary-panel {
      display: grid;
      grid-template-columns: 1fr;
      gap: 10px;
    }

    .big-stat,
    .mini-stat {
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--surface-soft);
      box-shadow: none;
    }

    .big-stat {
      padding: 16px;
    }

    .mini-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 10px;
    }

    .mini-stat {
      padding: 14px;
    }

    .big-stat span,
    .mini-stat span {
      display: block;
      color: var(--subtle);
      font-family: var(--mono);
      font-size: 11px;
      font-weight: 700;
      letter-spacing: 0;
      text-transform: uppercase;
    }

    .big-stat strong,
    .mini-stat strong {
      display: block;
      color: #111827;
      font-family: var(--mono);
      font-weight: 800;
      letter-spacing: 0;
      line-height: 1;
    }

    .big-stat strong {
      margin: 8px 0 6px;
      font-size: 44px;
    }

    .mini-stat strong {
      margin-top: 8px;
      font-size: 28px;
    }

    .control-bar {
      position: sticky;
      top: 0;
      z-index: 20;
      display: grid;
      grid-template-columns: minmax(0, 1fr) 230px;
      gap: 12px;
      margin: 12px 0;
      padding: 10px 0;
      background: rgba(246, 248, 251, 0.92);
      backdrop-filter: blur(14px);
    }

    .search-panel,
    .status-panel,
    .resource-section {
      border: 1px solid var(--line);
      border-radius: 8px;
      background: rgba(255, 255, 255, 0.94);
      box-shadow: var(--shadow);
    }

    .search-panel {
      display: grid;
      gap: 10px;
      padding: 12px;
    }

    .section-label {
      color: var(--subtle);
      font-family: var(--mono);
      font-size: 11px;
      font-weight: 700;
      letter-spacing: 0;
      text-transform: uppercase;
    }

    .search-box-wrap {
      display: flex;
      align-items: center;
      gap: 10px;
      min-height: 46px;
      padding: 0 12px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--surface);
    }

    .search-box-wrap:focus-within {
      border-color: var(--primary);
      box-shadow: 0 0 0 3px rgba(29, 78, 216, 0.14);
    }

    .search-box-wrap span {
      display: inline-grid;
      place-items: center;
      width: 26px;
      height: 26px;
      border-radius: 6px;
      background: var(--primary-soft);
      color: var(--primary);
      font-family: var(--mono);
      font-size: 13px;
      font-weight: 800;
    }

    .search-box {
      width: 100%;
      border: 0;
      outline: 0;
      background: transparent;
      color: var(--text);
      font-size: 15px;
    }

    .search-box::placeholder {
      color: var(--subtle);
    }

    .chip-row {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
    }

    .quick-chip {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-height: 34px;
      gap: 8px;
      padding: 0 10px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: var(--surface);
      color: var(--text);
      cursor: pointer;
      font-family: var(--mono);
      font-size: 12px;
      font-weight: 700;
      letter-spacing: 0;
      transition: border-color 160ms ease, background 160ms ease, color 160ms ease, box-shadow 160ms ease;
      touch-action: manipulation;
    }

    .quick-chip span {
      color: var(--subtle);
      font-weight: 800;
    }

    .quick-chip:hover,
    .quick-chip.active {
      border-color: var(--primary);
      background: var(--primary-soft);
      color: var(--primary);
    }

    .quick-chip:focus-visible,
    .resource-card:focus-visible {
      outline: 3px solid rgba(29, 78, 216, 0.24);
      outline-offset: 2px;
    }

    .status-panel {
      display: grid;
      align-content: center;
      gap: 6px;
      padding: 12px 14px;
    }

    .status-panel strong {
      display: block;
      color: #111827;
      font-family: var(--mono);
      font-size: 32px;
      line-height: 1;
    }

    .status-panel span,
    .status-panel div:last-child {
      color: var(--muted);
      font-size: 12px;
    }

    .stack {
      display: grid;
      gap: 12px;
    }

    .resource-section {
      overflow: hidden;
      padding: 0;
    }

    .section-head {
      position: sticky;
      top: 130px;
      z-index: 5;
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 16px;
      padding: 14px 16px;
      border-bottom: 1px solid var(--line);
      background: rgba(255, 255, 255, 0.96);
      backdrop-filter: blur(12px);
    }

    .section-copy h2 {
      margin: 0;
      color: #111827;
      font-size: 18px;
      font-weight: 760;
      line-height: 1.25;
      letter-spacing: 0;
    }

    .section-copy p {
      max-width: 860px;
      margin: 6px 0 0;
      color: var(--muted);
      font-size: 13px;
      line-height: 1.6;
    }

    .section-head > span {
      flex: 0 0 auto;
      min-height: 30px;
      padding: 6px 10px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: var(--surface-soft);
      color: var(--muted);
      font-family: var(--mono);
      font-size: 12px;
      font-weight: 800;
      white-space: nowrap;
    }

    .resource-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(360px, 1fr));
      gap: 0;
    }

    .resource-card {
      display: grid;
      grid-template-rows: auto auto 1fr auto auto;
      min-height: 178px;
      padding: 14px;
      border: 0;
      border-right: 1px solid var(--line);
      border-bottom: 1px solid var(--line);
      border-radius: 0;
      background: var(--surface);
      color: var(--text);
      text-decoration: none;
      transition: background 160ms ease, box-shadow 160ms ease;
    }

    .resource-card:hover {
      background: #f8fbff;
      box-shadow: inset 3px 0 0 var(--primary);
      transform: none;
    }

    .resource-top {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
      margin-bottom: 10px;
    }

    .resource-domain {
      min-width: 0;
      overflow: hidden;
      color: var(--primary);
      font-family: var(--mono);
      font-size: 12px;
      font-weight: 700;
      text-overflow: ellipsis;
      white-space: nowrap;
    }

    .resource-open {
      flex: 0 0 auto;
      color: var(--subtle);
      font-family: var(--mono);
      font-size: 11px;
      font-weight: 800;
      letter-spacing: 0;
      text-transform: uppercase;
    }

    .resource-meta {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 6px;
      margin-bottom: 10px;
    }

    .platform-badge,
    .resource-score {
      display: inline-flex;
      align-items: center;
      min-height: 26px;
      padding: 0 8px;
      border: 1px solid transparent;
      border-radius: 6px;
      font-family: var(--mono);
      font-size: 11px;
      font-weight: 800;
      letter-spacing: 0;
    }

    .platform-badge.is-newapi {
      color: var(--newapi);
      background: #dbeafe;
      border-color: #bfdbfe;
    }

    .platform-badge.is-sub2 {
      color: var(--sub2);
      background: #d1fae5;
      border-color: #a7f3d0;
    }

    .platform-badge.is-other {
      color: var(--other);
      background: #f1f5f9;
      border-color: #cbd5e1;
    }

    .platform-badge.is-review {
      color: var(--review);
      background: #fef3c7;
      border-color: #fde68a;
    }

    .platform-badge.is-failed {
      color: var(--failed);
      background: #ffe4e6;
      border-color: #fecdd3;
    }

    .resource-score {
      color: var(--muted);
      background: var(--surface-soft);
      border-color: var(--line);
    }

    .resource-card strong {
      display: block;
      margin: 0 0 10px;
      color: #111827;
      font-size: 15px;
      font-weight: 720;
      line-height: 1.45;
      word-break: break-word;
    }

    .resource-url {
      display: block;
      color: var(--muted);
      font-family: var(--mono);
      font-size: 11px;
      line-height: 1.55;
      word-break: break-all;
    }

    .resource-reason {
      display: block;
      margin-top: 10px;
      padding-top: 10px;
      border-top: 1px dashed var(--line-strong);
      color: #0f766e;
      font-family: var(--mono);
      font-size: 11px;
      line-height: 1.55;
      word-break: break-word;
    }

    .empty-state {
      display: none;
      padding: 24px;
      border: 1px dashed var(--line-strong);
      border-radius: 8px;
      background: var(--surface);
      color: var(--muted);
      text-align: center;
      box-shadow: none;
    }

    .empty-state.visible {
      display: block;
    }

    @media (max-width: 1080px) {
      .masthead,
      .control-bar {
        grid-template-columns: 1fr;
      }

      .control-bar {
        position: static;
      }

      .section-head {
        position: static;
      }
    }

    @media (max-width: 720px) {
      .page {
        width: min(100vw - 16px, 1560px);
        padding: 8px 0 24px;
      }

      .masthead {
        padding: 14px;
      }

      .masthead h1 {
        font-size: 28px;
      }

      .meta-pill,
      .quick-chip {
        width: 100%;
        justify-content: space-between;
      }

      .resource-grid {
        grid-template-columns: 1fr;
      }

      .resource-card {
        min-height: 0;
        border-right: 0;
      }
    }

    @media (prefers-reduced-motion: reduce) {
      *,
      *::before,
      *::after {
        scroll-behavior: auto !important;
        transition-duration: 0.01ms !important;
        animation-duration: 0.01ms !important;
      }
    }
    """
    html_doc = re.sub(r"<style>.*?</style>", f"<style>{dashboard_css}</style>", html_doc, flags=re.DOTALL)
    html_doc = html_doc.replace("AI Relay Navigator", "Rainbow Bridge Console")
    html_doc = html_doc.replace("AI Relay Hub", "Rainbow Bridge Console")
    return html_doc


_frontend_design_spotlight_renderer = render_spotlight_html


def render_spotlight_html(rows: list[dict], source_name: str) -> str:
    html_doc = _frontend_design_spotlight_renderer(rows, source_name)
    signal_yard_css = r"""
    :root {
      --paper: #edf4ef;
      --paper-2: #f8fbf5;
      --ink: #13221d;
      --muted: #63756e;
      --faint: #8fa29a;
      --line: #b8ccc2;
      --track: #d9e5df;
      --copper: #c9582c;
      --copper-soft: #ffe2d5;
      --newapi: #1e50d8;
      --sub2: #007c68;
      --other: #56636d;
      --review: #a85f00;
      --failed: #bd2545;
      --surface: rgba(255, 255, 250, 0.92);
      --surface-solid: #fffffb;
      --mono: "Cascadia Code", "JetBrains Mono", "Fira Code", Consolas, monospace;
      --display: "Bahnschrift", "Arial Narrow", "Microsoft YaHei", sans-serif;
      --body: "Aptos", "Segoe UI", "Microsoft YaHei", sans-serif;
    }

    * {
      box-sizing: border-box;
    }

    html {
      color-scheme: light;
      scroll-behavior: smooth;
    }

    body {
      margin: 0;
      min-height: 100vh;
      color: var(--ink);
      font-family: var(--body);
      font-size: 15px;
      line-height: 1.5;
      background:
        linear-gradient(90deg, transparent 0 94px, rgba(19, 34, 29, 0.08) 94px 95px, transparent 95px),
        linear-gradient(180deg, rgba(19, 34, 29, 0.045) 1px, transparent 1px),
        radial-gradient(circle at 92% 10%, rgba(201, 88, 44, 0.16), transparent 24%),
        var(--paper);
      background-size: 128px 100%, 100% 26px, auto, auto;
    }

    body::before {
      content: "";
      position: fixed;
      inset: 0;
      pointer-events: none;
      background:
        linear-gradient(90deg, transparent 0 22px, rgba(0, 124, 104, 0.28) 22px 24px, transparent 24px 48px, rgba(30, 80, 216, 0.26) 48px 50px, transparent 50px),
        linear-gradient(180deg, transparent 0 68%, rgba(201, 88, 44, 0.2) 68% 69%, transparent 69%);
      mask-image: linear-gradient(180deg, rgba(0,0,0,0.72), transparent 86%);
      opacity: 0.42;
    }

    .page {
      width: min(1620px, calc(100vw - 28px));
      margin: 0 auto;
      padding: 18px 0 48px;
      position: relative;
    }

    .masthead {
      position: relative;
      display: grid;
      grid-template-columns: minmax(0, 1fr) 344px;
      gap: 18px;
      min-height: 246px;
      padding: 24px;
      overflow: hidden;
      border: 1px solid var(--line);
      border-radius: 14px;
      background: linear-gradient(135deg, rgba(255,255,251,0.96), rgba(241,248,244,0.92));
      box-shadow: 0 16px 44px rgba(35, 54, 46, 0.12);
    }

    .masthead::after {
      content: "";
      position: absolute;
      right: -58px;
      top: 28px;
      width: 430px;
      height: 170px;
      border: 2px solid rgba(19, 34, 29, 0.14);
      border-left: 0;
      border-radius: 0 88px 88px 0;
      background:
        radial-gradient(circle at 18% 30%, var(--newapi) 0 5px, transparent 6px),
        radial-gradient(circle at 48% 72%, var(--sub2) 0 5px, transparent 6px),
        radial-gradient(circle at 78% 30%, var(--copper) 0 5px, transparent 6px),
        linear-gradient(90deg, transparent 0 18%, rgba(30,80,216,0.35) 18% 19%, transparent 19%),
        linear-gradient(180deg, transparent 0 30%, rgba(0,124,104,0.34) 30% 31%, transparent 31%);
      opacity: 0.75;
    }

    .eyebrow {
      display: inline-flex;
      width: fit-content;
      min-height: 30px;
      align-items: center;
      padding: 0 11px;
      border: 1px solid rgba(201, 88, 44, 0.36);
      border-radius: 99px;
      background: var(--copper-soft);
      color: #8f3517;
      font-family: var(--mono);
      font-size: 12px;
      font-weight: 800;
      letter-spacing: 0;
      text-transform: uppercase;
    }

    .masthead h1 {
      max-width: 760px;
      margin: 15px 0 0;
      color: var(--ink);
      font-family: var(--display);
      font-size: clamp(42px, 5vw, 82px);
      font-stretch: condensed;
      font-weight: 800;
      letter-spacing: 0;
      line-height: 0.92;
    }

    .masthead p {
      max-width: 760px;
      margin: 18px 0 0;
      color: var(--muted);
      font-size: 16px;
      line-height: 1.75;
    }

    .meta-row {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-top: 18px;
    }

    .meta-pill {
      display: inline-flex;
      align-items: center;
      min-height: 32px;
      padding: 0 10px;
      border: 1px solid var(--track);
      border-radius: 99px;
      background: rgba(255,255,251,0.78);
      color: var(--muted);
      font-family: var(--mono);
      font-size: 12px;
      letter-spacing: 0;
    }

    .summary-panel {
      position: relative;
      z-index: 1;
      display: grid;
      gap: 10px;
      align-content: end;
    }

    .big-stat,
    .mini-stat {
      border: 1px solid rgba(19, 34, 29, 0.14);
      border-radius: 10px;
      background: rgba(255,255,251,0.84);
      box-shadow: none;
    }

    .big-stat {
      padding: 18px;
      box-shadow: inset 0 -4px 0 rgba(201, 88, 44, 0.16);
    }

    .mini-grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 10px;
    }

    .mini-stat {
      padding: 14px;
    }

    .big-stat span,
    .mini-stat span {
      display: block;
      color: var(--faint);
      font-family: var(--mono);
      font-size: 11px;
      font-weight: 800;
      letter-spacing: 0;
      text-transform: uppercase;
    }

    .big-stat strong,
    .mini-stat strong {
      display: block;
      color: var(--ink);
      font-family: var(--display);
      font-size: 48px;
      font-weight: 800;
      line-height: 0.95;
      letter-spacing: 0;
    }

    .big-stat strong {
      margin: 8px 0;
      font-size: 68px;
    }

    .mini-stat strong {
      margin-top: 8px;
      font-size: 34px;
    }

    .control-bar {
      position: sticky;
      top: 0;
      z-index: 30;
      display: grid;
      grid-template-columns: minmax(0, 1fr) 236px;
      gap: 12px;
      margin: 12px 0;
      padding: 10px 0;
      background: rgba(237, 244, 239, 0.9);
      backdrop-filter: blur(16px);
    }

    .search-panel,
    .status-panel {
      border: 1px solid var(--line);
      border-radius: 12px;
      background: rgba(255, 255, 251, 0.9);
      box-shadow: 0 10px 30px rgba(35, 54, 46, 0.08);
    }

    .search-panel {
      display: grid;
      gap: 10px;
      padding: 12px;
    }

    .section-label {
      color: var(--faint);
      font-family: var(--mono);
      font-size: 11px;
      font-weight: 900;
      letter-spacing: 0;
      text-transform: uppercase;
    }

    .search-box-wrap {
      display: flex;
      align-items: center;
      gap: 10px;
      min-height: 48px;
      padding: 0 12px;
      border: 1px solid var(--track);
      border-radius: 10px;
      background: var(--surface-solid);
    }

    .search-box-wrap:focus-within {
      border-color: var(--copper);
      box-shadow: 0 0 0 4px rgba(201, 88, 44, 0.14);
    }

    .search-box-wrap span {
      display: inline-grid;
      place-items: center;
      width: 28px;
      height: 28px;
      border-radius: 50%;
      background: var(--ink);
      color: #fffffb;
      font-family: var(--mono);
      font-size: 13px;
      font-weight: 900;
    }

    .search-box {
      width: 100%;
      border: 0;
      outline: 0;
      background: transparent;
      color: var(--ink);
      font: inherit;
    }

    .search-box::placeholder {
      color: var(--faint);
    }

    .chip-row {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
    }

    .quick-chip {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-height: 36px;
      gap: 8px;
      padding: 0 12px;
      border: 1px solid var(--track);
      border-radius: 99px;
      background: var(--surface-solid);
      color: var(--ink);
      cursor: pointer;
      font-family: var(--mono);
      font-size: 12px;
      font-weight: 850;
      letter-spacing: 0;
      transition: transform 180ms ease, border-color 180ms ease, background 180ms ease, color 180ms ease;
      touch-action: manipulation;
    }

    .quick-chip span {
      color: var(--copper);
      font-weight: 900;
    }

    .quick-chip:hover,
    .quick-chip.active {
      transform: translateY(-1px);
      border-color: rgba(201, 88, 44, 0.5);
      background: var(--copper-soft);
      color: #8f3517;
    }

    .quick-chip:focus-visible,
    .resource-card:focus-visible {
      outline: 3px solid rgba(201, 88, 44, 0.28);
      outline-offset: 2px;
    }

    .status-panel {
      display: grid;
      align-content: center;
      gap: 6px;
      padding: 12px 14px;
    }

    .status-panel strong {
      display: block;
      color: var(--ink);
      font-family: var(--display);
      font-size: 42px;
      font-weight: 800;
      line-height: 0.95;
    }

    .status-panel span,
    .status-panel div:last-child {
      color: var(--muted);
      font-size: 12px;
    }

    .stack {
      display: grid;
      gap: 14px;
    }

    .resource-section {
      position: relative;
      overflow: hidden;
      padding: 0 0 0 18px;
      border: 1px solid var(--line);
      border-radius: 14px;
      background: rgba(255,255,251,0.88);
      box-shadow: 0 12px 34px rgba(35, 54, 46, 0.08);
    }

    .resource-section::before {
      content: "";
      position: absolute;
      left: 8px;
      top: 0;
      bottom: 0;
      width: 3px;
      background: var(--other);
      opacity: 0.72;
    }

    .resource-section[data-group*="newapi"]::before {
      background: var(--newapi);
    }

    .resource-section[data-group*="sub2"]::before {
      background: var(--sub2);
    }

    .resource-section[data-group*="待"],
    .resource-section[data-group*="review"] {
      --route-color: var(--review);
    }

    .resource-section[data-group*="探"],
    .resource-section[data-group*="fail"] {
      --route-color: var(--failed);
    }

    .section-head {
      position: sticky;
      top: 132px;
      z-index: 5;
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 16px;
      padding: 15px 16px 14px;
      border-bottom: 1px solid var(--track);
      background: rgba(255,255,251,0.94);
      backdrop-filter: blur(14px);
    }

    .section-copy h2 {
      margin: 0;
      color: var(--ink);
      font-family: var(--display);
      font-size: 24px;
      font-weight: 800;
      line-height: 1.05;
      letter-spacing: 0;
    }

    .section-copy p {
      max-width: 850px;
      margin: 7px 0 0;
      color: var(--muted);
      font-size: 13px;
      line-height: 1.6;
    }

    .section-head > span {
      flex: 0 0 auto;
      min-height: 32px;
      padding: 7px 11px;
      border: 1px solid var(--track);
      border-radius: 99px;
      background: var(--surface-solid);
      color: var(--muted);
      font-family: var(--mono);
      font-size: 12px;
      font-weight: 900;
      white-space: nowrap;
    }

    .resource-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(342px, 1fr));
      gap: 0;
    }

    .resource-card {
      position: relative;
      display: grid;
      grid-template-rows: auto auto 1fr auto auto;
      min-height: 176px;
      padding: 15px 15px 15px 20px;
      border: 0;
      border-right: 1px solid var(--track);
      border-bottom: 1px solid var(--track);
      border-radius: 0;
      background: rgba(255,255,251,0.72);
      color: var(--ink);
      text-decoration: none;
      transition: background 180ms ease, box-shadow 180ms ease, transform 180ms ease;
    }

    .resource-card::before {
      content: "";
      position: absolute;
      left: 8px;
      top: 19px;
      width: 7px;
      height: 7px;
      border-radius: 50%;
      background: var(--faint);
      box-shadow: 0 0 0 4px rgba(143, 162, 154, 0.16);
    }

    .resource-card:has(.is-newapi)::before {
      background: var(--newapi);
      box-shadow: 0 0 0 4px rgba(30, 80, 216, 0.13);
    }

    .resource-card:has(.is-sub2)::before {
      background: var(--sub2);
      box-shadow: 0 0 0 4px rgba(0, 124, 104, 0.13);
    }

    .resource-card:has(.is-review)::before {
      background: var(--review);
      box-shadow: 0 0 0 4px rgba(168, 95, 0, 0.13);
    }

    .resource-card:has(.is-failed)::before {
      background: var(--failed);
      box-shadow: 0 0 0 4px rgba(189, 37, 69, 0.13);
    }

    .resource-card:hover {
      z-index: 2;
      transform: translateY(-2px);
      background: var(--surface-solid);
      box-shadow: 0 16px 30px rgba(35, 54, 46, 0.12);
    }

    .resource-top {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
      margin-bottom: 10px;
    }

    .resource-domain {
      min-width: 0;
      overflow: hidden;
      color: var(--muted);
      font-family: var(--mono);
      font-size: 12px;
      font-weight: 850;
      text-overflow: ellipsis;
      white-space: nowrap;
    }

    .resource-open {
      flex: 0 0 auto;
      color: var(--copper);
      font-family: var(--mono);
      font-size: 11px;
      font-weight: 900;
      letter-spacing: 0;
      text-transform: uppercase;
    }

    .resource-meta {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 6px;
      margin-bottom: 10px;
    }

    .platform-badge,
    .resource-score {
      display: inline-flex;
      align-items: center;
      min-height: 26px;
      padding: 0 9px;
      border: 1px solid transparent;
      border-radius: 99px;
      font-family: var(--mono);
      font-size: 11px;
      font-weight: 900;
      letter-spacing: 0;
    }

    .platform-badge.is-newapi {
      color: var(--newapi);
      background: #dfe8ff;
      border-color: #b9c9ff;
    }

    .platform-badge.is-sub2 {
      color: var(--sub2);
      background: #d9f4ea;
      border-color: #a8ddcf;
    }

    .platform-badge.is-other {
      color: var(--other);
      background: #eef2f3;
      border-color: #ccd6d8;
    }

    .platform-badge.is-review {
      color: var(--review);
      background: #ffefc7;
      border-color: #ffd27e;
    }

    .platform-badge.is-failed {
      color: var(--failed);
      background: #ffe1e6;
      border-color: #f5b7c3;
    }

    .resource-score {
      color: var(--muted);
      background: rgba(255,255,251,0.78);
      border-color: var(--track);
    }

    .resource-card strong {
      display: block;
      margin: 0 0 10px;
      color: var(--ink);
      font-size: 15px;
      font-weight: 760;
      line-height: 1.45;
      word-break: break-word;
    }

    .resource-url {
      display: block;
      color: var(--muted);
      font-family: var(--mono);
      font-size: 11px;
      line-height: 1.55;
      word-break: break-all;
    }

    .resource-reason {
      display: block;
      margin-top: 10px;
      padding-top: 10px;
      border-top: 1px dashed var(--line);
      color: #0e6358;
      font-family: var(--mono);
      font-size: 11px;
      line-height: 1.55;
      word-break: break-word;
    }

    .empty-state {
      display: none;
      padding: 26px;
      border: 1px dashed var(--line);
      border-radius: 14px;
      background: var(--surface);
      color: var(--muted);
      text-align: center;
      box-shadow: none;
    }

    .empty-state.visible {
      display: block;
    }

    @media (max-width: 1080px) {
      .masthead,
      .control-bar {
        grid-template-columns: 1fr;
      }

      .control-bar,
      .section-head {
        position: static;
      }

      .masthead::after {
        opacity: 0.28;
      }
    }

    @media (max-width: 720px) {
      .page {
        width: min(100vw - 14px, 1620px);
        padding: 8px 0 28px;
      }

      .masthead {
        min-height: 0;
        padding: 17px;
      }

      .masthead h1 {
        font-size: 38px;
      }

      .meta-pill,
      .quick-chip {
        width: 100%;
        justify-content: space-between;
      }

      .resource-grid {
        grid-template-columns: 1fr;
      }

      .resource-card {
        min-height: 0;
        border-right: 0;
      }
    }

    @media (prefers-reduced-motion: reduce) {
      *,
      *::before,
      *::after {
        scroll-behavior: auto !important;
        transition-duration: 0.01ms !important;
        animation-duration: 0.01ms !important;
      }
    }
    """
    html_doc = re.sub(r"<style>.*?</style>", f"<style>{signal_yard_css}</style>", html_doc, flags=re.DOTALL)
    html_doc = re.sub(r"<title>.*?</title>", "<title>中转信号分拣台</title>", html_doc, count=1, flags=re.DOTALL)
    html_doc = re.sub(r"<h1>.*?</h1>", "<h1>中转信号分拣台</h1>", html_doc, count=1, flags=re.DOTALL)
    html_doc = re.sub(
        r"<p>.*?</p>",
        "<p>把 AI 中转站里的链接当作一张路由图来扫：蓝线归 NewAPI，绿线归 Sub2API，铜色提醒你复核，红色说明探测失败。</p>",
        html_doc,
        count=1,
        flags=re.DOTALL,
    )
    html_doc = html_doc.replace("Rainbow Bridge Console", "Signal Yard")
    html_doc = html_doc.replace("Search And Focus", "Route filter")
    return html_doc


_readable_directory_renderer = render_spotlight_html


def render_spotlight_html(rows: list[dict], source_name: str) -> str:
    html_doc = _readable_directory_renderer(rows, source_name)
    directory_css = r"""
    :root {
      --bg: #f5f4ee;
      --surface: #fffefa;
      --surface-soft: #faf8f1;
      --ink: #171717;
      --text: #242424;
      --muted: #60656f;
      --subtle: #8b919b;
      --line: #d8d3c6;
      --line-strong: #bdb6a7;
      --blue: #2657d8;
      --green: #00806a;
      --amber: #b45d0b;
      --red: #c12b45;
      --gray: #626c76;
      --focus: rgba(38, 87, 216, 0.22);
      --shadow: 0 12px 28px rgba(37, 33, 25, 0.08);
      --mono: "Cascadia Code", "JetBrains Mono", "Fira Code", Consolas, monospace;
      --sans: "Segoe UI", "Microsoft YaHei", "PingFang SC", sans-serif;
      --display: "Microsoft YaHei UI", "Segoe UI", sans-serif;
    }

    * {
      box-sizing: border-box;
    }

    html {
      color-scheme: light;
      scroll-behavior: smooth;
    }

    body {
      margin: 0;
      min-height: 100vh;
      color: var(--text);
      background:
        linear-gradient(180deg, rgba(255,255,255,0.58), transparent 260px),
        var(--bg);
      font-family: var(--sans);
      font-size: 16px;
      line-height: 1.55;
    }

    body::before {
      display: none;
    }

    .page {
      width: min(1500px, calc(100vw - 32px));
      margin: 0 auto;
      padding: 18px 0 44px;
    }

    .masthead {
      display: grid;
      grid-template-columns: minmax(0, 1fr) 330px;
      gap: 18px;
      padding: 26px;
      border: 1px solid var(--line);
      border-radius: 10px;
      background: var(--surface);
      box-shadow: var(--shadow);
    }

    .masthead::after {
      display: none;
    }

    .eyebrow {
      display: inline-flex;
      width: fit-content;
      align-items: center;
      min-height: 30px;
      padding: 0 11px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: var(--surface-soft);
      color: var(--muted);
      font-family: var(--mono);
      font-size: 12px;
      font-weight: 800;
      letter-spacing: 0;
      text-transform: uppercase;
    }

    .masthead h1 {
      max-width: none;
      margin: 14px 0 0;
      color: var(--ink);
      font-family: var(--display);
      font-size: clamp(34px, 4vw, 58px);
      font-weight: 850;
      line-height: 1.08;
      letter-spacing: 0;
    }

    .masthead p {
      max-width: 850px;
      margin: 14px 0 0;
      color: var(--muted);
      font-size: 16px;
      line-height: 1.75;
    }

    .meta-row {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-top: 18px;
    }

    .meta-pill {
      display: inline-flex;
      align-items: center;
      min-height: 32px;
      padding: 0 10px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: #ffffff;
      color: var(--muted);
      font-family: var(--mono);
      font-size: 12px;
      letter-spacing: 0;
    }

    .summary-panel {
      display: grid;
      gap: 10px;
      align-content: stretch;
    }

    .big-stat,
    .mini-stat {
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--surface-soft);
      box-shadow: none;
    }

    .big-stat {
      padding: 18px;
    }

    .mini-grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 10px;
    }

    .mini-stat {
      padding: 14px;
    }

    .big-stat span,
    .mini-stat span {
      display: block;
      color: var(--subtle);
      font-family: var(--mono);
      font-size: 11px;
      font-weight: 800;
      letter-spacing: 0;
      text-transform: uppercase;
    }

    .big-stat strong,
    .mini-stat strong {
      display: block;
      color: var(--ink);
      font-family: var(--mono);
      font-weight: 900;
      line-height: 1;
      letter-spacing: 0;
    }

    .big-stat strong {
      margin: 10px 0 8px;
      font-size: 46px;
    }

    .mini-stat strong {
      margin-top: 8px;
      font-size: 28px;
    }

    .control-bar {
      position: sticky;
      top: 0;
      z-index: 40;
      display: grid;
      grid-template-columns: minmax(0, 1fr) 230px;
      gap: 12px;
      margin: 14px 0;
      padding: 10px 0;
      background: rgba(245, 244, 238, 0.94);
      backdrop-filter: blur(14px);
    }

    .search-panel,
    .status-panel,
    .resource-section {
      border: 1px solid var(--line);
      border-radius: 10px;
      background: var(--surface);
      box-shadow: var(--shadow);
    }

    .search-panel {
      display: grid;
      gap: 10px;
      padding: 12px;
    }

    .section-label {
      color: var(--subtle);
      font-family: var(--mono);
      font-size: 11px;
      font-weight: 900;
      letter-spacing: 0;
      text-transform: uppercase;
    }

    .search-box-wrap {
      display: flex;
      align-items: center;
      gap: 10px;
      min-height: 48px;
      padding: 0 12px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #ffffff;
    }

    .search-box-wrap:focus-within {
      border-color: var(--blue);
      box-shadow: 0 0 0 4px var(--focus);
    }

    .search-box-wrap span {
      display: inline-grid;
      place-items: center;
      width: 28px;
      height: 28px;
      border-radius: 6px;
      background: var(--ink);
      color: #ffffff;
      font-family: var(--mono);
      font-size: 13px;
      font-weight: 900;
    }

    .search-box {
      width: 100%;
      border: 0;
      outline: 0;
      background: transparent;
      color: var(--ink);
      font: inherit;
    }

    .search-box::placeholder {
      color: var(--subtle);
    }

    .chip-row {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
    }

    .quick-chip {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-height: 38px;
      gap: 8px;
      padding: 0 12px;
      border: 1px solid var(--line);
      border-radius: 7px;
      background: #ffffff;
      color: var(--ink);
      cursor: pointer;
      font-family: var(--mono);
      font-size: 12px;
      font-weight: 850;
      letter-spacing: 0;
      transition: border-color 160ms ease, background 160ms ease, color 160ms ease, transform 160ms ease;
      touch-action: manipulation;
    }

    .quick-chip span {
      color: var(--subtle);
      font-weight: 900;
    }

    .quick-chip:hover,
    .quick-chip.active {
      transform: translateY(-1px);
      border-color: var(--blue);
      background: #e8eeff;
      color: var(--blue);
    }

    .quick-chip:focus-visible,
    .resource-card:focus-visible {
      outline: 3px solid var(--focus);
      outline-offset: 2px;
    }

    .status-panel {
      display: grid;
      align-content: center;
      gap: 6px;
      padding: 12px 14px;
    }

    .status-panel strong {
      display: block;
      color: var(--ink);
      font-family: var(--mono);
      font-size: 34px;
      font-weight: 900;
      line-height: 1;
    }

    .status-panel span,
    .status-panel div:last-child {
      color: var(--muted);
      font-size: 12px;
    }

    .stack {
      display: grid;
      gap: 16px;
    }

    .resource-section {
      overflow: hidden;
      padding: 0;
    }

    .resource-section::before {
      display: none;
    }

    .section-head {
      position: static;
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 16px;
      padding: 18px 18px 14px;
      border-bottom: 1px solid var(--line);
      background: var(--surface-soft);
      backdrop-filter: none;
    }

    .section-copy h2 {
      margin: 0;
      color: var(--ink);
      font-family: var(--display);
      font-size: 24px;
      font-weight: 850;
      line-height: 1.2;
      letter-spacing: 0;
    }

    .section-copy p {
      max-width: 900px;
      margin: 7px 0 0;
      color: var(--muted);
      font-size: 14px;
      line-height: 1.65;
    }

    .section-head > span {
      flex: 0 0 auto;
      min-height: 34px;
      padding: 7px 11px;
      border: 1px solid var(--line);
      border-radius: 7px;
      background: #ffffff;
      color: var(--muted);
      font-family: var(--mono);
      font-size: 12px;
      font-weight: 900;
      white-space: nowrap;
    }

    .resource-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(380px, 1fr));
      gap: 12px;
      padding: 14px;
    }

    .resource-card {
      position: relative;
      display: grid;
      grid-template-rows: auto auto 1fr auto auto;
      min-height: 194px;
      padding: 16px 16px 16px 18px;
      border: 1px solid var(--line);
      border-left: 7px solid var(--gray);
      border-radius: 9px;
      background: #ffffff;
      color: var(--text);
      text-decoration: none;
      box-shadow: 0 1px 0 rgba(37, 33, 25, 0.04);
      transition: border-color 160ms ease, box-shadow 160ms ease, transform 160ms ease;
    }

    .resource-card::before {
      display: none;
    }

    .resource-card:has(.is-newapi) {
      border-left-color: var(--blue);
    }

    .resource-card:has(.is-sub2) {
      border-left-color: var(--green);
    }

    .resource-card:has(.is-other) {
      border-left-color: var(--gray);
    }

    .resource-card:has(.is-review) {
      border-left-color: var(--amber);
    }

    .resource-card:has(.is-failed) {
      border-left-color: var(--red);
    }

    .resource-card:hover {
      transform: translateY(-2px);
      border-color: var(--line-strong);
      box-shadow: 0 14px 24px rgba(37, 33, 25, 0.11);
      background: #ffffff;
    }

    .resource-top {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      margin-bottom: 12px;
    }

    .resource-domain {
      min-width: 0;
      overflow: hidden;
      color: var(--ink);
      font-family: var(--mono);
      font-size: 13px;
      font-weight: 900;
      text-overflow: ellipsis;
      white-space: nowrap;
    }

    .resource-open {
      flex: 0 0 auto;
      color: var(--blue);
      font-family: var(--mono);
      font-size: 11px;
      font-weight: 900;
      letter-spacing: 0;
      text-transform: uppercase;
    }

    .resource-meta {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 7px;
      margin-bottom: 12px;
    }

    .platform-badge,
    .resource-score {
      display: inline-flex;
      align-items: center;
      min-height: 28px;
      padding: 0 9px;
      border: 1px solid transparent;
      border-radius: 7px;
      font-family: var(--mono);
      font-size: 12px;
      font-weight: 900;
      letter-spacing: 0;
    }

    .platform-badge.is-newapi {
      color: var(--blue);
      background: #e8eeff;
      border-color: #c8d5ff;
    }

    .platform-badge.is-sub2 {
      color: var(--green);
      background: #ddf5ee;
      border-color: #bce5d9;
    }

    .platform-badge.is-other {
      color: var(--gray);
      background: #eef1f3;
      border-color: #d4d9de;
    }

    .platform-badge.is-review {
      color: var(--amber);
      background: #fff0d3;
      border-color: #ffd89a;
    }

    .platform-badge.is-failed {
      color: var(--red);
      background: #ffe5ea;
      border-color: #f5bdc8;
    }

    .resource-score {
      color: var(--muted);
      background: var(--surface-soft);
      border-color: var(--line);
    }

    .resource-card strong {
      display: block;
      margin: 0 0 11px;
      color: var(--ink);
      font-size: 17px;
      font-weight: 850;
      line-height: 1.42;
      word-break: break-word;
    }

    .resource-url {
      display: block;
      color: var(--muted);
      font-family: var(--mono);
      font-size: 12px;
      line-height: 1.6;
      word-break: break-all;
    }

    .resource-reason {
      display: block;
      margin-top: 12px;
      padding-top: 12px;
      border-top: 1px dashed var(--line);
      color: #0b6b5b;
      font-family: var(--mono);
      font-size: 12px;
      line-height: 1.6;
      word-break: break-word;
    }

    .empty-state {
      display: none;
      padding: 28px;
      border: 1px dashed var(--line-strong);
      border-radius: 10px;
      background: var(--surface);
      color: var(--muted);
      text-align: center;
      box-shadow: none;
    }

    .empty-state.visible {
      display: block;
    }

    @media (max-width: 1080px) {
      .masthead,
      .control-bar {
        grid-template-columns: 1fr;
      }

      .control-bar {
        position: static;
      }
    }

    @media (max-width: 720px) {
      .page {
        width: min(100vw - 16px, 1500px);
        padding: 10px 0 28px;
      }

      .masthead {
        padding: 18px;
      }

      .masthead h1 {
        font-size: 34px;
      }

      .section-head {
        display: grid;
      }

      .meta-pill,
      .quick-chip {
        width: 100%;
        justify-content: space-between;
      }

      .resource-grid {
        grid-template-columns: 1fr;
        padding: 10px;
      }

      .resource-card {
        min-height: 0;
      }
    }

    @media (prefers-reduced-motion: reduce) {
      *,
      *::before,
      *::after {
        scroll-behavior: auto !important;
        transition-duration: 0.01ms !important;
        animation-duration: 0.01ms !important;
      }
    }
    """
    html_doc = re.sub(r"<style>.*?</style>", f"<style>{directory_css}</style>", html_doc, flags=re.DOTALL)
    html_doc = re.sub(r"<title>.*?</title>", "<title>AI 中转站导航台</title>", html_doc, count=1, flags=re.DOTALL)
    html_doc = re.sub(r"<h1>.*?</h1>", "<h1>AI 中转站导航台</h1>", html_doc, count=1, flags=re.DOTALL)
    html_doc = re.sub(
        r"<p>.*?</p>",
        "<p>把所有链接按识别结果分组展示。先看蓝色 NewAPI 和绿色 Sub2API，黄色适合复核，红色表示当前没探测到可靠结果。</p>",
        html_doc,
        count=1,
        flags=re.DOTALL,
    )
    html_doc = html_doc.replace("Signal Yard", "Relay Index")
    html_doc = html_doc.replace("Route filter", "Search and filters")
    return html_doc


_neon_directory_renderer = render_spotlight_html


def render_spotlight_html(rows: list[dict], source_name: str) -> str:
    html_doc = _neon_directory_renderer(rows, source_name)
    neon_css = r"""
    :root {
      --bg: #07090f;
      --bg-2: #0c1019;
      --panel: #101622;
      --panel-2: #151d2b;
      --card: #0f1724;
      --card-hover: #141f30;
      --text: #f4f7fb;
      --muted: #a7b1c2;
      --subtle: #6f7b8f;
      --line: rgba(176, 190, 214, 0.16);
      --line-strong: rgba(176, 190, 214, 0.32);
      --newapi: #4f8cff;
      --sub2: #31d0aa;
      --other: #9aa6b8;
      --review: #ffbf47;
      --failed: #ff5573;
      --hot: #ff6b35;
      --glow: 0 20px 60px rgba(0, 0, 0, 0.42);
      --mono: "Cascadia Code", "JetBrains Mono", "Fira Code", Consolas, monospace;
      --sans: "Segoe UI", "Microsoft YaHei", "PingFang SC", sans-serif;
      --display: "Bahnschrift", "Microsoft YaHei UI", "Segoe UI", sans-serif;
    }

    * {
      box-sizing: border-box;
    }

    html {
      color-scheme: dark;
      scroll-behavior: smooth;
    }

    body {
      margin: 0;
      min-height: 100vh;
      color: var(--text);
      font-family: var(--sans);
      font-size: 15px;
      line-height: 1.55;
      background:
        linear-gradient(120deg, rgba(79, 140, 255, 0.12), transparent 32%),
        linear-gradient(250deg, rgba(49, 208, 170, 0.10), transparent 30%),
        radial-gradient(circle at 78% 12%, rgba(255, 107, 53, 0.16), transparent 26%),
        var(--bg);
    }

    body::before {
      content: "";
      position: fixed;
      inset: 0;
      pointer-events: none;
      background:
        linear-gradient(rgba(255,255,255,0.035) 1px, transparent 1px),
        linear-gradient(90deg, rgba(255,255,255,0.035) 1px, transparent 1px);
      background-size: 36px 36px;
      mask-image: linear-gradient(180deg, rgba(0,0,0,0.75), transparent 90%);
    }

    .page {
      position: relative;
      width: min(1560px, calc(100vw - 28px));
      margin: 0 auto;
      padding: 18px 0 48px;
    }

    .masthead {
      position: relative;
      overflow: hidden;
      display: grid;
      grid-template-columns: minmax(0, 1fr) 360px;
      gap: 18px;
      min-height: 260px;
      padding: 28px;
      border: 1px solid var(--line);
      border-radius: 22px;
      background:
        linear-gradient(135deg, rgba(21, 29, 43, 0.96), rgba(9, 13, 22, 0.94)),
        var(--panel);
      box-shadow: var(--glow);
    }

    .masthead::after {
      content: "";
      position: absolute;
      right: -90px;
      top: -90px;
      width: 420px;
      height: 420px;
      border-radius: 50%;
      background:
        radial-gradient(circle, rgba(79, 140, 255, 0.28), transparent 58%),
        conic-gradient(from 90deg, transparent, rgba(49,208,170,0.28), transparent, rgba(255,107,53,0.24), transparent);
      filter: blur(2px);
      opacity: 0.9;
    }

    .eyebrow {
      position: relative;
      z-index: 1;
      display: inline-flex;
      width: fit-content;
      align-items: center;
      min-height: 32px;
      padding: 0 12px;
      border: 1px solid rgba(79, 140, 255, 0.38);
      border-radius: 999px;
      background: rgba(79, 140, 255, 0.12);
      color: #b8d0ff;
      font-family: var(--mono);
      font-size: 12px;
      font-weight: 800;
      letter-spacing: 0;
      text-transform: uppercase;
    }

    .masthead h1 {
      position: relative;
      z-index: 1;
      max-width: 820px;
      margin: 16px 0 0;
      color: var(--text);
      font-family: var(--display);
      font-size: clamp(42px, 6vw, 86px);
      font-weight: 850;
      line-height: 0.94;
      letter-spacing: 0;
    }

    .masthead p {
      position: relative;
      z-index: 1;
      max-width: 820px;
      margin: 18px 0 0;
      color: var(--muted);
      font-size: 16px;
      line-height: 1.75;
    }

    .meta-row {
      position: relative;
      z-index: 1;
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-top: 18px;
    }

    .meta-pill {
      display: inline-flex;
      align-items: center;
      min-height: 34px;
      padding: 0 11px;
      border: 1px solid var(--line);
      border-radius: 999px;
      background: rgba(255,255,255,0.06);
      color: var(--muted);
      font-family: var(--mono);
      font-size: 12px;
      letter-spacing: 0;
    }

    .summary-panel {
      position: relative;
      z-index: 1;
      display: grid;
      gap: 12px;
      align-content: end;
    }

    .big-stat,
    .mini-stat {
      border: 1px solid var(--line);
      border-radius: 16px;
      background: rgba(255, 255, 255, 0.065);
      box-shadow: none;
      backdrop-filter: blur(12px);
    }

    .big-stat {
      padding: 20px;
    }

    .mini-grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 12px;
    }

    .mini-stat {
      padding: 16px;
    }

    .big-stat span,
    .mini-stat span {
      display: block;
      color: var(--subtle);
      font-family: var(--mono);
      font-size: 11px;
      font-weight: 800;
      letter-spacing: 0;
      text-transform: uppercase;
    }

    .big-stat strong,
    .mini-stat strong {
      display: block;
      color: var(--text);
      font-family: var(--mono);
      font-weight: 900;
      line-height: 1;
      letter-spacing: 0;
    }

    .big-stat strong {
      margin: 10px 0 8px;
      font-size: 58px;
    }

    .mini-stat strong {
      margin-top: 8px;
      font-size: 30px;
    }

    .control-bar {
      position: sticky;
      top: 0;
      z-index: 40;
      display: grid;
      grid-template-columns: minmax(0, 1fr) 240px;
      gap: 12px;
      margin: 14px 0;
      padding: 10px 0;
      background: rgba(7, 9, 15, 0.86);
      backdrop-filter: blur(18px);
    }

    .search-panel,
    .status-panel,
    .resource-section {
      border: 1px solid var(--line);
      border-radius: 18px;
      background: rgba(16, 22, 34, 0.92);
      box-shadow: var(--glow);
    }

    .search-panel {
      display: grid;
      gap: 12px;
      padding: 14px;
    }

    .section-label {
      color: var(--subtle);
      font-family: var(--mono);
      font-size: 11px;
      font-weight: 900;
      letter-spacing: 0;
      text-transform: uppercase;
    }

    .search-box-wrap {
      display: flex;
      align-items: center;
      gap: 11px;
      min-height: 52px;
      padding: 0 14px;
      border: 1px solid var(--line);
      border-radius: 14px;
      background: rgba(255,255,255,0.055);
    }

    .search-box-wrap:focus-within {
      border-color: var(--newapi);
      box-shadow: 0 0 0 4px rgba(79, 140, 255, 0.16);
    }

    .search-box-wrap span {
      display: inline-grid;
      place-items: center;
      width: 30px;
      height: 30px;
      border-radius: 10px;
      background: rgba(79, 140, 255, 0.18);
      color: #b8d0ff;
      font-family: var(--mono);
      font-size: 13px;
      font-weight: 900;
    }

    .search-box {
      width: 100%;
      border: 0;
      outline: 0;
      background: transparent;
      color: var(--text);
      font: inherit;
    }

    .search-box::placeholder {
      color: var(--subtle);
    }

    .chip-row {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
    }

    .quick-chip {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-height: 38px;
      gap: 8px;
      padding: 0 12px;
      border: 1px solid var(--line);
      border-radius: 999px;
      background: rgba(255,255,255,0.055);
      color: var(--text);
      cursor: pointer;
      font-family: var(--mono);
      font-size: 12px;
      font-weight: 850;
      letter-spacing: 0;
      transition: transform 160ms ease, border-color 160ms ease, background 160ms ease, color 160ms ease;
      touch-action: manipulation;
    }

    .quick-chip span {
      color: var(--subtle);
      font-weight: 900;
    }

    .quick-chip:hover,
    .quick-chip.active {
      transform: translateY(-1px);
      border-color: var(--newapi);
      background: rgba(79, 140, 255, 0.14);
      color: #cfe0ff;
    }

    .quick-chip:focus-visible,
    .resource-card:focus-visible {
      outline: 3px solid rgba(79, 140, 255, 0.28);
      outline-offset: 3px;
    }

    .status-panel {
      display: grid;
      align-content: center;
      gap: 6px;
      padding: 14px 16px;
    }

    .status-panel strong {
      display: block;
      color: var(--text);
      font-family: var(--mono);
      font-size: 36px;
      font-weight: 900;
      line-height: 1;
    }

    .status-panel span,
    .status-panel div:last-child {
      color: var(--muted);
      font-size: 12px;
    }

    .stack {
      display: grid;
      gap: 16px;
    }

    .resource-section {
      overflow: hidden;
      padding: 0;
    }

    .resource-section::before {
      display: none;
    }

    .section-head {
      position: static;
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 16px;
      padding: 18px 20px 16px;
      border-bottom: 1px solid var(--line);
      background: linear-gradient(90deg, rgba(255,255,255,0.07), transparent);
      backdrop-filter: none;
    }

    .section-copy h2 {
      margin: 0;
      color: var(--text);
      font-family: var(--display);
      font-size: 28px;
      font-weight: 850;
      line-height: 1.08;
      letter-spacing: 0;
    }

    .section-copy p {
      max-width: 900px;
      margin: 8px 0 0;
      color: var(--muted);
      font-size: 14px;
      line-height: 1.65;
    }

    .section-head > span {
      flex: 0 0 auto;
      min-height: 34px;
      padding: 7px 11px;
      border: 1px solid var(--line);
      border-radius: 999px;
      background: rgba(255,255,255,0.06);
      color: var(--muted);
      font-family: var(--mono);
      font-size: 12px;
      font-weight: 900;
      white-space: nowrap;
    }

    .resource-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(330px, 1fr));
      gap: 14px;
      padding: 16px;
    }

    .resource-card {
      position: relative;
      display: grid;
      grid-template-rows: auto auto 1fr auto auto;
      min-height: 210px;
      padding: 16px;
      border: 1px solid var(--line);
      border-radius: 18px;
      background:
        linear-gradient(180deg, rgba(255,255,255,0.065), rgba(255,255,255,0.025)),
        var(--card);
      color: var(--text);
      text-decoration: none;
      box-shadow: none;
      transition: transform 160ms ease, border-color 160ms ease, background 160ms ease, box-shadow 160ms ease;
    }

    .resource-card::before {
      content: "";
      position: absolute;
      inset: 0 auto 0 0;
      width: 5px;
      border-radius: 18px 0 0 18px;
      background: var(--other);
      opacity: 0.96;
      display: block;
    }

    .resource-card:has(.is-newapi)::before {
      background: var(--newapi);
      box-shadow: 0 0 22px rgba(79, 140, 255, 0.48);
    }

    .resource-card:has(.is-sub2)::before {
      background: var(--sub2);
      box-shadow: 0 0 22px rgba(49, 208, 170, 0.42);
    }

    .resource-card:has(.is-review)::before {
      background: var(--review);
      box-shadow: 0 0 22px rgba(255, 191, 71, 0.38);
    }

    .resource-card:has(.is-failed)::before {
      background: var(--failed);
      box-shadow: 0 0 22px rgba(255, 85, 115, 0.38);
    }

    .resource-card:hover {
      transform: translateY(-4px);
      border-color: var(--line-strong);
      background:
        linear-gradient(180deg, rgba(255,255,255,0.10), rgba(255,255,255,0.04)),
        var(--card-hover);
      box-shadow: 0 18px 40px rgba(0, 0, 0, 0.28);
    }

    .resource-top {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      margin-bottom: 12px;
      padding-left: 5px;
    }

    .resource-domain {
      min-width: 0;
      overflow: hidden;
      color: #d8e1ef;
      font-family: var(--mono);
      font-size: 13px;
      font-weight: 900;
      text-overflow: ellipsis;
      white-space: nowrap;
    }

    .resource-open {
      flex: 0 0 auto;
      color: var(--hot);
      font-family: var(--mono);
      font-size: 11px;
      font-weight: 900;
      letter-spacing: 0;
      text-transform: uppercase;
    }

    .resource-meta {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 7px;
      margin-bottom: 12px;
    }

    .platform-badge,
    .resource-score {
      display: inline-flex;
      align-items: center;
      min-height: 28px;
      padding: 0 10px;
      border: 1px solid transparent;
      border-radius: 999px;
      font-family: var(--mono);
      font-size: 12px;
      font-weight: 900;
      letter-spacing: 0;
    }

    .platform-badge.is-newapi {
      color: #dce8ff;
      background: rgba(79, 140, 255, 0.18);
      border-color: rgba(79, 140, 255, 0.34);
    }

    .platform-badge.is-sub2 {
      color: #d8fff4;
      background: rgba(49, 208, 170, 0.16);
      border-color: rgba(49, 208, 170, 0.32);
    }

    .platform-badge.is-other {
      color: #e4e9f2;
      background: rgba(154, 166, 184, 0.14);
      border-color: rgba(154, 166, 184, 0.26);
    }

    .platform-badge.is-review {
      color: #fff0c2;
      background: rgba(255, 191, 71, 0.16);
      border-color: rgba(255, 191, 71, 0.32);
    }

    .platform-badge.is-failed {
      color: #ffe2e8;
      background: rgba(255, 85, 115, 0.16);
      border-color: rgba(255, 85, 115, 0.32);
    }

    .resource-score {
      color: var(--muted);
      background: rgba(255,255,255,0.06);
      border-color: var(--line);
    }

    .resource-card strong {
      display: block;
      margin: 0 0 12px;
      color: var(--text);
      font-size: 18px;
      font-weight: 850;
      line-height: 1.38;
      word-break: break-word;
    }

    .resource-url {
      display: block;
      color: var(--muted);
      font-family: var(--mono);
      font-size: 12px;
      line-height: 1.65;
      word-break: break-all;
    }

    .resource-reason {
      display: block;
      margin-top: 12px;
      padding-top: 12px;
      border-top: 1px dashed var(--line-strong);
      color: #8ff0db;
      font-family: var(--mono);
      font-size: 12px;
      line-height: 1.6;
      word-break: break-word;
    }

    .empty-state {
      display: none;
      padding: 28px;
      border: 1px dashed var(--line-strong);
      border-radius: 18px;
      background: var(--panel);
      color: var(--muted);
      text-align: center;
      box-shadow: none;
    }

    .empty-state.visible {
      display: block;
    }

    @media (max-width: 1080px) {
      .masthead,
      .control-bar {
        grid-template-columns: 1fr;
      }

      .control-bar {
        position: static;
      }
    }

    @media (max-width: 720px) {
      .page {
        width: min(100vw - 16px, 1560px);
        padding: 10px 0 28px;
      }

      .masthead {
        min-height: 0;
        padding: 18px;
      }

      .masthead h1 {
        font-size: 40px;
      }

      .section-head {
        display: grid;
      }

      .meta-pill,
      .quick-chip {
        width: 100%;
        justify-content: space-between;
      }

      .resource-grid {
        grid-template-columns: 1fr;
        padding: 12px;
      }

      .resource-card {
        min-height: 0;
      }
    }

    @media (prefers-reduced-motion: reduce) {
      *,
      *::before,
      *::after {
        scroll-behavior: auto !important;
        transition-duration: 0.01ms !important;
        animation-duration: 0.01ms !important;
      }
    }
    """
    html_doc = re.sub(r"<style>.*?</style>", f"<style>{neon_css}</style>", html_doc, flags=re.DOTALL)
    html_doc = re.sub(r"<title>.*?</title>", "<title>AI Relay Dock</title>", html_doc, count=1, flags=re.DOTALL)
    html_doc = re.sub(r"<h1>.*?</h1>", "<h1>AI Relay Dock</h1>", html_doc, count=1, flags=re.DOTALL)
    html_doc = re.sub(
        r"<p>.*?</p>",
        "<p>一个专门筛 AI 中转站的开发者导航。NewAPI、Sub2API、待复核和探测失败全部拆开，打开链接前先看状态。</p>",
        html_doc,
        count=1,
        flags=re.DOTALL,
    )
    html_doc = html_doc.replace("Relay Index", "Relay Dock")
    html_doc = html_doc.replace("Search and filters", "Search / Filter")
    return html_doc


_pricing_overlay_renderer = render_spotlight_html


def render_spotlight_html(rows: list[dict], source_name: str) -> str:
    html_doc = _pricing_overlay_renderer(rows, source_name)
    domain_options = "".join(
        f'<option value="{html.escape(row["domain"])}">{html.escape(row["title"])}</option>'
        for row in sorted(rows, key=lambda item: (item["domain"], item["title"]))
        if row.get("domain")
    )
    calculator_css = r"""
    .calculator-panel {
      margin-bottom: 16px;
      border: 1px solid var(--line);
      border-radius: 18px;
      background: rgba(16, 22, 34, 0.94);
      box-shadow: var(--glow);
      overflow: hidden;
    }

    .calculator-head {
      padding: 18px 20px 14px;
      border-bottom: 1px solid var(--line);
      background: linear-gradient(90deg, rgba(255,255,255,0.06), transparent);
    }

    .calculator-head h2 {
      margin: 0;
      color: var(--text);
      font-family: var(--display);
      font-size: 26px;
      font-weight: 850;
      line-height: 1.08;
      letter-spacing: 0;
    }

    .calculator-head p {
      margin: 8px 0 0;
      color: var(--muted);
      font-size: 14px;
      line-height: 1.65;
    }

    .calculator-body {
      display: grid;
      gap: 14px;
      padding: 16px;
    }

    .calculator-grid,
    .ratio-grid,
    .result-grid {
      display: grid;
      gap: 12px;
    }

    .calculator-grid {
      grid-template-columns: repeat(4, minmax(0, 1fr));
    }

    .ratio-grid {
      grid-template-columns: repeat(3, minmax(0, 1fr));
    }

    .result-grid {
      grid-template-columns: repeat(4, minmax(0, 1fr));
    }

    .field,
    .result-card {
      border: 1px solid var(--line);
      border-radius: 16px;
      background: rgba(255,255,255,0.05);
    }

    .field {
      padding: 12px;
    }

    .field label,
    .result-card span {
      display: block;
      color: var(--subtle);
      font-family: var(--mono);
      font-size: 11px;
      font-weight: 900;
      letter-spacing: 0;
      text-transform: uppercase;
    }

    .field input,
    .field select {
      width: 100%;
      margin-top: 8px;
      min-height: 42px;
      border: 1px solid var(--line);
      border-radius: 12px;
      padding: 0 12px;
      background: rgba(255,255,255,0.04);
      color: var(--text);
      font: inherit;
      outline: 0;
    }

    .field input:focus,
    .field select:focus {
      border-color: var(--newapi);
      box-shadow: 0 0 0 4px rgba(79, 140, 255, 0.16);
    }

    .field small,
    .ratio-note {
      display: block;
      margin-top: 8px;
      color: var(--muted);
      font-size: 12px;
      line-height: 1.55;
    }

    .ratio-note strong {
      color: var(--review);
      font-weight: 800;
    }

    .result-card {
      padding: 14px;
      min-height: 92px;
      display: grid;
      align-content: start;
      gap: 8px;
    }

    .result-card strong {
      color: var(--text);
      font-family: var(--mono);
      font-size: 28px;
      font-weight: 900;
      line-height: 1.05;
      letter-spacing: 0;
      word-break: break-word;
    }

    .calculator-actions {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      align-items: center;
    }

    .calc-button {
      min-height: 40px;
      padding: 0 14px;
      border: 1px solid var(--line);
      border-radius: 999px;
      background: rgba(255,255,255,0.06);
      color: var(--text);
      cursor: pointer;
      font-family: var(--mono);
      font-size: 12px;
      font-weight: 900;
      transition: transform 160ms ease, border-color 160ms ease, background 160ms ease;
    }

    .calc-button:hover {
      transform: translateY(-1px);
      border-color: var(--newapi);
      background: rgba(79, 140, 255, 0.16);
    }

    .calc-button.-danger:hover {
      border-color: var(--failed);
      background: rgba(255, 85, 115, 0.14);
    }

    .calc-status {
      color: var(--muted);
      font-size: 13px;
      line-height: 1.5;
    }

    .resource-card.has-pricing-profile {
      box-shadow: 0 18px 40px rgba(0, 0, 0, 0.22);
    }

    .pricing-summary {
      display: grid;
      gap: 8px;
      margin-top: 12px;
      padding-top: 12px;
      border-top: 1px dashed var(--line-strong);
    }

    .pricing-summary__top {
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
    }

    .pricing-chip {
      display: inline-flex;
      align-items: center;
      min-height: 26px;
      padding: 0 9px;
      border-radius: 999px;
      font-family: var(--mono);
      font-size: 11px;
      font-weight: 900;
      letter-spacing: 0;
      border: 1px solid rgba(255,255,255,0.08);
      background: rgba(255,255,255,0.06);
      color: var(--text);
    }

    .pricing-chip.-hot {
      background: rgba(255, 107, 53, 0.14);
      color: #ffd4c7;
      border-color: rgba(255, 107, 53, 0.26);
    }

    .pricing-chip.-cool {
      background: rgba(79, 140, 255, 0.14);
      color: #cfe0ff;
      border-color: rgba(79, 140, 255, 0.26);
    }

    .pricing-chip.-mint {
      background: rgba(49, 208, 170, 0.14);
      color: #d6fff5;
      border-color: rgba(49, 208, 170, 0.24);
    }

    .pricing-summary__meta {
      color: var(--muted);
      font-family: var(--mono);
      font-size: 11px;
      line-height: 1.6;
      word-break: break-word;
    }

    @media (max-width: 1180px) {
      .calculator-grid,
      .result-grid {
        grid-template-columns: repeat(2, minmax(0, 1fr));
      }
    }

    @media (max-width: 720px) {
      .calculator-grid,
      .ratio-grid,
      .result-grid {
        grid-template-columns: 1fr;
      }
    }
    """
    calculator_html = f"""
    <section class="calculator-panel" id="pricingCalculator">
      <div class="calculator-head">
        <h2>Quota Calculator</h2>
        <p>按你截图里的思路来算：先设定输入 / 缓存 / 输出单价和使用占比，再乘套餐倍率，得到真实综合费率、1 美元可用 token、1 元可用 token 和套餐总 token。</p>
      </div>
      <div class="calculator-body">
        <div class="calculator-grid">
          <div class="field">
            <label for="pricingSite">站点 / 域名</label>
            <input id="pricingSite" list="siteDomainList" placeholder="例如 api.example.com" />
          </div>
          <div class="field">
            <label for="pricingModel">大模型</label>
            <input id="pricingModel" placeholder="例如 GPT-5.5" />
          </div>
          <div class="field">
            <label for="pricingPackageUsd">套餐美元额度 ($)</label>
            <input id="pricingPackageUsd" type="number" step="0.0001" value="10" />
          </div>
          <div class="field">
            <label for="pricingUsdPerRmb">1 元人民币可用额度 ($/¥)</label>
            <input id="pricingUsdPerRmb" type="number" step="0.0001" value="10" />
          </div>
          <div class="field">
            <label for="pricingMultiplier">套餐倍率</label>
            <input id="pricingMultiplier" type="number" step="0.0001" value="1.2" />
          </div>
          <div class="field">
            <label for="pricingInputPrice">输入价格 ($/M)</label>
            <input id="pricingInputPrice" type="number" step="0.0001" value="5" />
          </div>
          <div class="field">
            <label for="pricingCachePrice">缓存价格 ($/M)</label>
            <input id="pricingCachePrice" type="number" step="0.0001" value="0.5" />
          </div>
          <div class="field">
            <label for="pricingOutputPrice">输出价格 ($/M)</label>
            <input id="pricingOutputPrice" type="number" step="0.0001" value="30" />
          </div>
        </div>

        <div class="ratio-grid">
          <div class="field">
            <label for="pricingInputRatio">输入占比 (%)</label>
            <input id="pricingInputRatio" type="number" step="0.0001" value="4.69" />
          </div>
          <div class="field">
            <label for="pricingCacheRatio">缓存占比 (%)</label>
            <input id="pricingCacheRatio" type="number" step="0.0001" value="94.98" />
          </div>
          <div class="field">
            <label for="pricingOutputRatio">输出占比 (%)</label>
            <input id="pricingOutputRatio" type="number" step="0.0001" value="0.33" />
          </div>
        </div>

        <div class="ratio-note" id="pricingRatioNote">当前按 1M 混合消耗来算，三个占比最好加起来等于 <strong>100%</strong>。</div>

        <div class="result-grid">
          <div class="result-card"><span>输入成本</span><strong id="resultInputCost">0</strong></div>
          <div class="result-card"><span>缓存成本</span><strong id="resultCacheCost">0</strong></div>
          <div class="result-card"><span>输出成本</span><strong id="resultOutputCost">0</strong></div>
          <div class="result-card"><span>总成本</span><strong id="resultTotalCost">0</strong></div>
          <div class="result-card"><span>真实综合费率 ($/1M)</span><strong id="resultEffectiveRate">0</strong></div>
          <div class="result-card"><span>1 美元可用 token (M/$)</span><strong id="resultTokensPerUsd">0</strong></div>
          <div class="result-card"><span>1 元可用 token (M/¥)</span><strong id="resultTokensPerRmb">0</strong></div>
          <div class="result-card"><span>套餐总可放 token (M)</span><strong id="resultPackageTokens">0</strong></div>
        </div>

        <div class="calculator-actions">
          <button class="calc-button" id="savePricingProfile" type="button">保存并展示到卡片</button>
          <button class="calc-button -danger" id="clearPricingProfile" type="button">清除当前站点数据</button>
          <div class="calc-status" id="pricingStatus">当前只是本地计算，保存后会显示在对应站点卡片上。</div>
        </div>
      </div>
      <datalist id="siteDomainList">
        {domain_options}
      </datalist>
    </section>
    """
    calculator_js = r"""
    <script>
      (() => {
        const STORAGE_KEY = 'relay_pricing_profiles_v1';
        const ids = {
          site: document.getElementById('pricingSite'),
          model: document.getElementById('pricingModel'),
          packageUsd: document.getElementById('pricingPackageUsd'),
          usdPerRmb: document.getElementById('pricingUsdPerRmb'),
          multiplier: document.getElementById('pricingMultiplier'),
          inputPrice: document.getElementById('pricingInputPrice'),
          cachePrice: document.getElementById('pricingCachePrice'),
          outputPrice: document.getElementById('pricingOutputPrice'),
          inputRatio: document.getElementById('pricingInputRatio'),
          cacheRatio: document.getElementById('pricingCacheRatio'),
          outputRatio: document.getElementById('pricingOutputRatio'),
          ratioNote: document.getElementById('pricingRatioNote'),
          status: document.getElementById('pricingStatus'),
          save: document.getElementById('savePricingProfile'),
          clear: document.getElementById('clearPricingProfile'),
          resultInputCost: document.getElementById('resultInputCost'),
          resultCacheCost: document.getElementById('resultCacheCost'),
          resultOutputCost: document.getElementById('resultOutputCost'),
          resultTotalCost: document.getElementById('resultTotalCost'),
          resultEffectiveRate: document.getElementById('resultEffectiveRate'),
          resultTokensPerUsd: document.getElementById('resultTokensPerUsd'),
          resultTokensPerRmb: document.getElementById('resultTokensPerRmb'),
          resultPackageTokens: document.getElementById('resultPackageTokens'),
        };

        function normalizeDomain(value) {
          return String(value || '')
            .trim()
            .toLowerCase()
            .replace(/^https?:\/\//, '')
            .replace(/\/.*$/, '');
        }

        function parseNumber(node) {
          return Number.parseFloat(node.value || '0') || 0;
        }

        function formatNumber(value, digits = 4) {
          if (!Number.isFinite(value)) return '0';
          return value.toFixed(digits).replace(/\.?0+$/, '');
        }

        function loadStore() {
          try {
            return JSON.parse(localStorage.getItem(STORAGE_KEY) || '{}');
          } catch (error) {
            return {};
          }
        }

        function saveStore(store) {
          localStorage.setItem(STORAGE_KEY, JSON.stringify(store));
        }

        function computePricing() {
          const inputRatio = parseNumber(ids.inputRatio) / 100;
          const cacheRatio = parseNumber(ids.cacheRatio) / 100;
          const outputRatio = parseNumber(ids.outputRatio) / 100;
          const ratioSum = (inputRatio + cacheRatio + outputRatio) * 100;

          const inputCost = parseNumber(ids.inputPrice) * inputRatio;
          const cacheCost = parseNumber(ids.cachePrice) * cacheRatio;
          const outputCost = parseNumber(ids.outputPrice) * outputRatio;
          const totalCost = inputCost + cacheCost + outputCost;
          const effectiveRate = totalCost * parseNumber(ids.multiplier);
          const tokensPerUsd = effectiveRate > 0 ? 1 / effectiveRate : 0;
          const tokensPerRmb = tokensPerUsd * parseNumber(ids.usdPerRmb);
          const packageTokens = tokensPerUsd * parseNumber(ids.packageUsd);

          ids.resultInputCost.textContent = formatNumber(inputCost);
          ids.resultCacheCost.textContent = formatNumber(cacheCost);
          ids.resultOutputCost.textContent = formatNumber(outputCost);
          ids.resultTotalCost.textContent = formatNumber(totalCost);
          ids.resultEffectiveRate.textContent = formatNumber(effectiveRate, 5);
          ids.resultTokensPerUsd.textContent = formatNumber(tokensPerUsd, 6);
          ids.resultTokensPerRmb.textContent = formatNumber(tokensPerRmb, 4);
          ids.resultPackageTokens.textContent = formatNumber(packageTokens, 4);

          const ratioDiff = Math.abs(ratioSum - 100);
          if (ratioDiff > 0.0001) {
            ids.ratioNote.innerHTML = `当前占比合计 <strong>${formatNumber(ratioSum, 2)}%</strong>，建议调到 100%。`;
          } else {
            ids.ratioNote.innerHTML = '当前按 1M 混合消耗来算，三个占比已经对齐到 <strong>100%</strong>。';
          }

          return {
            model: ids.model.value.trim(),
            packageUsd: parseNumber(ids.packageUsd),
            usdPerRmb: parseNumber(ids.usdPerRmb),
            multiplier: parseNumber(ids.multiplier),
            inputPrice: parseNumber(ids.inputPrice),
            cachePrice: parseNumber(ids.cachePrice),
            outputPrice: parseNumber(ids.outputPrice),
            inputRatioPct: parseNumber(ids.inputRatio),
            cacheRatioPct: parseNumber(ids.cacheRatio),
            outputRatioPct: parseNumber(ids.outputRatio),
            inputCost,
            cacheCost,
            outputCost,
            totalCost,
            effectiveRate,
            tokensPerUsd,
            tokensPerRmb,
            packageTokens,
            ratioSum,
          };
        }

        function updateCards() {
          const store = loadStore();
          document.querySelectorAll('.resource-card').forEach((card) => {
            const domain = normalizeDomain(card.querySelector('.resource-domain')?.textContent || card.getAttribute('href'));
            const oldNode = card.querySelector('.pricing-summary');
            if (oldNode) oldNode.remove();
            card.classList.remove('has-pricing-profile');
            const profile = store[domain];
            if (!profile) return;

            card.classList.add('has-pricing-profile');
            const summary = document.createElement('div');
            summary.className = 'pricing-summary';
            summary.innerHTML = `
              <div class="pricing-summary__top">
                ${profile.model ? `<span class="pricing-chip">${profile.model}</span>` : ''}
                <span class="pricing-chip -hot">真费率 $${formatNumber(profile.effectiveRate, 5)}/M</span>
                <span class="pricing-chip -cool">1$ ≈ ${formatNumber(profile.tokensPerUsd, 4)}M</span>
                <span class="pricing-chip -mint">1￥ ≈ ${formatNumber(profile.tokensPerRmb, 4)}M</span>
              </div>
              <div class="pricing-summary__meta">套餐总量 ≈ ${formatNumber(profile.packageTokens, 4)}M | 占比 ${formatNumber(profile.inputRatioPct, 2)} / ${formatNumber(profile.cacheRatioPct, 2)} / ${formatNumber(profile.outputRatioPct, 2)}</div>
            `;
            card.appendChild(summary);
          });
        }

        function fillForm(profile) {
          if (!profile) return;
          ids.model.value = profile.model || '';
          ids.packageUsd.value = profile.packageUsd ?? '';
          ids.usdPerRmb.value = profile.usdPerRmb ?? '';
          ids.multiplier.value = profile.multiplier ?? '';
          ids.inputPrice.value = profile.inputPrice ?? '';
          ids.cachePrice.value = profile.cachePrice ?? '';
          ids.outputPrice.value = profile.outputPrice ?? '';
          ids.inputRatio.value = profile.inputRatioPct ?? '';
          ids.cacheRatio.value = profile.cacheRatioPct ?? '';
          ids.outputRatio.value = profile.outputRatioPct ?? '';
          computePricing();
        }

        function saveCurrentProfile() {
          const domain = normalizeDomain(ids.site.value);
          if (!domain) {
            ids.status.textContent = '先填一个站点域名，再保存。';
            return;
          }
          const computed = computePricing();
          const store = loadStore();
          store[domain] = { domain, ...computed };
          saveStore(store);
          updateCards();
          ids.status.textContent = `${domain} 的成本数据已保存，并展示到对应卡片上。`;
        }

        function clearCurrentProfile() {
          const domain = normalizeDomain(ids.site.value);
          if (!domain) {
            ids.status.textContent = '先填一个站点域名，再清除。';
            return;
          }
          const store = loadStore();
          delete store[domain];
          saveStore(store);
          updateCards();
          ids.status.textContent = `${domain} 的成本数据已清除。`;
        }

        ids.site.addEventListener('change', () => {
          const domain = normalizeDomain(ids.site.value);
          const profile = loadStore()[domain];
          if (profile) {
            fillForm(profile);
            ids.status.textContent = `${domain} 已存在保存数据，已自动填回计算器。`;
          } else {
            ids.status.textContent = `${domain || '当前站点'} 还没有保存的数据。`;
          }
        });

        [
          ids.packageUsd,
          ids.usdPerRmb,
          ids.multiplier,
          ids.inputPrice,
          ids.cachePrice,
          ids.outputPrice,
          ids.inputRatio,
          ids.cacheRatio,
          ids.outputRatio,
        ].forEach((node) => node.addEventListener('input', computePricing));

        ids.save.addEventListener('click', saveCurrentProfile);
        ids.clear.addEventListener('click', clearCurrentProfile);

        computePricing();
        updateCards();
      })();
    </script>
    """
    html_doc = html_doc.replace('<section id="sectionStack" class="stack">', calculator_html + '\n    <section id="sectionStack" class="stack">', 1)
    html_doc = html_doc.replace("</style>", calculator_css + "\n  </style>", 1)
    html_doc = html_doc.replace("</body>", calculator_js + "\n</body>", 1)
    return html_doc


_observatory_style_renderer = render_spotlight_html


def render_spotlight_html(rows: list[dict], source_name: str) -> str:
    html_doc = _observatory_style_renderer(rows, source_name)
    observatory_css = r"""
    :root {
      --bg: #0b0d10;
      --bg-2: #12161a;
      --panel: #111418;
      --panel-2: #171b20;
      --card: #13171c;
      --card-2: #191f26;
      --text: #f3efe5;
      --muted: #aba393;
      --subtle: #7b7468;
      --line: rgba(225, 216, 197, 0.14);
      --line-strong: rgba(225, 216, 197, 0.28);
      --accent: #d9a441;
      --accent-soft: rgba(217, 164, 65, 0.14);
      --newapi: #78a9ff;
      --sub2: #58d0a7;
      --other: #9aa3ad;
      --review: #f4b860;
      --failed: #ff7d73;
      --shadow: 0 18px 44px rgba(0, 0, 0, 0.34);
      --mono: "Cascadia Code", "JetBrains Mono", Consolas, monospace;
      --display: "Bahnschrift", "Arial Narrow", "Microsoft YaHei UI", sans-serif;
      --sans: "Segoe UI", "Microsoft YaHei", "PingFang SC", sans-serif;
    }

    * {
      box-sizing: border-box;
    }

    html {
      color-scheme: dark;
      scroll-behavior: smooth;
    }

    body {
      margin: 0;
      min-height: 100vh;
      color: var(--text);
      font-family: var(--sans);
      font-size: 15px;
      line-height: 1.55;
      background:
        radial-gradient(circle at 14% 0%, rgba(217, 164, 65, 0.12), transparent 26%),
        radial-gradient(circle at 88% 12%, rgba(120, 169, 255, 0.10), transparent 24%),
        linear-gradient(180deg, #0a0c0f, #0e1115 38%, #0a0c0f 100%);
    }

    body::before {
      content: "";
      position: fixed;
      inset: 0;
      pointer-events: none;
      background-image:
        linear-gradient(rgba(255,255,255,0.03) 1px, transparent 1px),
        linear-gradient(90deg, rgba(255,255,255,0.03) 1px, transparent 1px);
      background-size: 34px 34px;
      mask-image: linear-gradient(180deg, rgba(0,0,0,0.76), transparent 90%);
    }

    .page {
      width: min(1540px, calc(100vw - 26px));
      margin: 0 auto;
      padding: 16px 0 44px;
    }

    .observatory-nav {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-bottom: 12px;
    }

    .observatory-nav a {
      display: inline-flex;
      align-items: center;
      min-height: 34px;
      padding: 0 12px;
      border: 1px solid var(--line);
      border-radius: 999px;
      background: rgba(255,255,255,0.04);
      color: var(--muted);
      font-family: var(--mono);
      font-size: 12px;
      font-weight: 800;
      text-decoration: none;
      transition: border-color 160ms ease, color 160ms ease, background 160ms ease;
    }

    .observatory-nav a:hover {
      border-color: rgba(217, 164, 65, 0.36);
      color: var(--text);
      background: rgba(217, 164, 65, 0.08);
    }

    .observatory-nav a.is-live {
      border-color: rgba(217, 164, 65, 0.38);
      color: #f6d293;
      background: rgba(217, 164, 65, 0.12);
    }

    .masthead {
      position: relative;
      overflow: hidden;
      display: grid;
      grid-template-columns: minmax(0, 1fr) 350px;
      gap: 18px;
      min-height: 256px;
      padding: 24px;
      border: 1px solid var(--line);
      border-radius: 22px;
      background:
        linear-gradient(180deg, rgba(255,255,255,0.03), transparent),
        linear-gradient(135deg, rgba(23, 27, 32, 0.98), rgba(13, 16, 20, 0.96));
      box-shadow: var(--shadow);
    }

    .masthead::after {
      content: "";
      position: absolute;
      right: -70px;
      top: -46px;
      width: 320px;
      height: 320px;
      border-radius: 50%;
      border: 1px solid rgba(217, 164, 65, 0.12);
      background:
        radial-gradient(circle at center, rgba(217, 164, 65, 0.08), transparent 60%),
        radial-gradient(circle at 34% 42%, rgba(120, 169, 255, 0.18), transparent 12%),
        radial-gradient(circle at 62% 66%, rgba(88, 208, 167, 0.18), transparent 12%);
    }

    .eyebrow {
      display: inline-flex;
      width: fit-content;
      align-items: center;
      min-height: 30px;
      padding: 0 10px;
      border: 1px solid rgba(217, 164, 65, 0.26);
      border-radius: 999px;
      background: rgba(217, 164, 65, 0.10);
      color: #f0c36f;
      font-family: var(--mono);
      font-size: 12px;
      font-weight: 800;
      letter-spacing: 0;
      text-transform: uppercase;
    }

    .masthead h1 {
      max-width: 820px;
      margin: 16px 0 0;
      color: var(--text);
      font-family: var(--display);
      font-size: clamp(40px, 5.4vw, 78px);
      font-weight: 850;
      line-height: 0.95;
      letter-spacing: 0;
    }

    .masthead p {
      max-width: 800px;
      margin: 16px 0 0;
      color: var(--muted);
      font-size: 16px;
      line-height: 1.75;
    }

    .meta-row {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-top: 18px;
    }

    .meta-pill {
      display: inline-flex;
      align-items: center;
      min-height: 34px;
      padding: 0 11px;
      border: 1px solid var(--line);
      border-radius: 999px;
      background: rgba(255,255,255,0.04);
      color: var(--muted);
      font-family: var(--mono);
      font-size: 12px;
      letter-spacing: 0;
    }

    .summary-panel {
      display: grid;
      gap: 12px;
      align-content: end;
      position: relative;
      z-index: 1;
    }

    .big-stat,
    .mini-stat {
      border: 1px solid var(--line);
      border-radius: 18px;
      background: rgba(255,255,255,0.045);
      backdrop-filter: blur(10px);
      box-shadow: none;
    }

    .big-stat {
      padding: 18px;
    }

    .mini-grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 12px;
    }

    .mini-stat {
      padding: 14px;
    }

    .big-stat span,
    .mini-stat span {
      display: block;
      color: var(--subtle);
      font-family: var(--mono);
      font-size: 11px;
      font-weight: 900;
      letter-spacing: 0;
      text-transform: uppercase;
    }

    .big-stat strong,
    .mini-stat strong {
      display: block;
      color: var(--text);
      font-family: var(--mono);
      font-weight: 900;
      line-height: 1;
      letter-spacing: 0;
    }

    .big-stat strong {
      margin: 10px 0 8px;
      font-size: 52px;
    }

    .mini-stat strong {
      margin-top: 8px;
      font-size: 28px;
    }

    .control-bar {
      position: sticky;
      top: 0;
      z-index: 35;
      display: grid;
      grid-template-columns: minmax(0, 1fr) 230px;
      gap: 12px;
      margin: 14px 0;
      padding: 10px 0;
      background: rgba(11, 13, 16, 0.88);
      backdrop-filter: blur(18px);
    }

    .search-panel,
    .status-panel,
    .resource-section,
    .calculator-panel {
      border: 1px solid var(--line);
      border-radius: 18px;
      background: rgba(17, 20, 24, 0.94);
      box-shadow: var(--shadow);
    }

    .search-panel {
      display: grid;
      gap: 10px;
      padding: 12px;
    }

    .section-label {
      color: var(--subtle);
      font-family: var(--mono);
      font-size: 11px;
      font-weight: 900;
      letter-spacing: 0;
      text-transform: uppercase;
    }

    .search-box-wrap,
    .field input,
    .field select {
      border: 1px solid var(--line);
      background: rgba(255,255,255,0.05);
      color: var(--text);
    }

    .search-box-wrap {
      display: flex;
      align-items: center;
      gap: 10px;
      min-height: 50px;
      padding: 0 13px;
      border-radius: 14px;
    }

    .search-box-wrap:focus-within,
    .field input:focus,
    .field select:focus {
      border-color: rgba(217, 164, 65, 0.44);
      box-shadow: 0 0 0 4px rgba(217, 164, 65, 0.12);
    }

    .search-box-wrap span {
      display: inline-grid;
      place-items: center;
      width: 28px;
      height: 28px;
      border-radius: 9px;
      background: rgba(217, 164, 65, 0.14);
      color: #f5cf8a;
      font-family: var(--mono);
      font-size: 13px;
      font-weight: 900;
    }

    .search-box {
      width: 100%;
      border: 0;
      outline: 0;
      background: transparent;
      color: var(--text);
      font: inherit;
    }

    .search-box::placeholder,
    .field input::placeholder {
      color: var(--subtle);
    }

    .chip-row {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
    }

    .quick-chip,
    .calc-button {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-height: 38px;
      gap: 8px;
      padding: 0 12px;
      border: 1px solid var(--line);
      border-radius: 999px;
      background: rgba(255,255,255,0.05);
      color: var(--text);
      cursor: pointer;
      font-family: var(--mono);
      font-size: 12px;
      font-weight: 900;
      letter-spacing: 0;
      transition: transform 160ms ease, border-color 160ms ease, background 160ms ease, color 160ms ease;
      touch-action: manipulation;
    }

    .quick-chip span {
      color: var(--subtle);
    }

    .quick-chip:hover,
    .quick-chip.active,
    .calc-button:hover {
      transform: translateY(-1px);
      border-color: rgba(217, 164, 65, 0.38);
      background: rgba(217, 164, 65, 0.10);
      color: #f6d293;
    }

    .calc-button.-danger:hover {
      border-color: rgba(255, 125, 115, 0.42);
      background: rgba(255, 125, 115, 0.10);
      color: #ffc7c2;
    }

    .quick-chip:focus-visible,
    .resource-card:focus-visible,
    .calc-button:focus-visible {
      outline: 3px solid rgba(217, 164, 65, 0.16);
      outline-offset: 3px;
    }

    .status-panel {
      display: grid;
      align-content: center;
      gap: 6px;
      padding: 12px 14px;
    }

    .status-panel strong {
      display: block;
      color: var(--text);
      font-family: var(--mono);
      font-size: 34px;
      font-weight: 900;
      line-height: 1;
    }

    .status-panel span,
    .status-panel div:last-child,
    .calc-status,
    .field small,
    .ratio-note {
      color: var(--muted);
      font-size: 12px;
    }

    .stack {
      display: grid;
      gap: 16px;
    }

    .resource-section {
      overflow: hidden;
      padding: 0;
    }

    .section-head {
      position: static;
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 16px;
      padding: 18px 18px 14px;
      border-bottom: 1px solid var(--line);
      background: linear-gradient(90deg, rgba(217, 164, 65, 0.08), transparent 42%);
    }

    .section-copy h2 {
      margin: 0;
      color: var(--text);
      font-family: var(--display);
      font-size: 24px;
      font-weight: 850;
      line-height: 1.08;
      letter-spacing: 0;
    }

    .section-copy p {
      max-width: 900px;
      margin: 8px 0 0;
      color: var(--muted);
      font-size: 14px;
      line-height: 1.65;
    }

    .section-head > span {
      flex: 0 0 auto;
      min-height: 34px;
      padding: 7px 11px;
      border: 1px solid var(--line);
      border-radius: 999px;
      background: rgba(255,255,255,0.04);
      color: var(--muted);
      font-family: var(--mono);
      font-size: 12px;
      font-weight: 900;
      white-space: nowrap;
    }

    .resource-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(330px, 1fr));
      gap: 14px;
      padding: 14px;
    }

    .resource-card {
      position: relative;
      display: grid;
      grid-template-rows: auto auto 1fr auto auto;
      min-height: 206px;
      padding: 16px;
      border: 1px solid var(--line);
      border-radius: 18px;
      background:
        linear-gradient(180deg, rgba(255,255,255,0.05), rgba(255,255,255,0.02)),
        var(--card);
      color: var(--text);
      text-decoration: none;
      transition: transform 160ms ease, border-color 160ms ease, background 160ms ease, box-shadow 160ms ease;
    }

    .resource-card::before {
      content: "";
      position: absolute;
      left: 16px;
      top: 16px;
      width: 10px;
      height: 10px;
      border-radius: 50%;
      background: var(--other);
      box-shadow: 0 0 0 4px rgba(154, 166, 184, 0.08);
    }

    .resource-card:has(.is-newapi)::before {
      background: var(--newapi);
      box-shadow: 0 0 0 4px rgba(120, 169, 255, 0.10);
    }

    .resource-card:has(.is-favorite)::before {
      background: var(--accent);
      box-shadow: 0 0 0 4px rgba(217, 164, 65, 0.14);
    }

    .resource-card:has(.is-favorite) {
      border-color: rgba(217, 164, 65, 0.34);
      background:
        linear-gradient(180deg, rgba(217, 164, 65, 0.10), rgba(255,255,255,0.02)),
        var(--card-2);
      box-shadow:
        0 22px 44px rgba(0, 0, 0, 0.28),
        0 0 0 1px rgba(217, 164, 65, 0.08) inset;
      overflow: hidden;
    }

    .resource-card:has(.is-favorite)::after {
      content: "";
      position: absolute;
      inset: -20% auto auto -30%;
      width: 60%;
      height: 180%;
      transform: rotate(24deg);
      background: linear-gradient(90deg, transparent, rgba(255, 229, 163, 0.12), transparent);
      pointer-events: none;
    }

    .resource-card:has(.is-sub2)::before {
      background: var(--sub2);
      box-shadow: 0 0 0 4px rgba(88, 208, 167, 0.10);
    }

    .resource-card:has(.is-review)::before {
      background: var(--review);
      box-shadow: 0 0 0 4px rgba(244, 184, 96, 0.10);
    }

    .resource-card:has(.is-failed)::before {
      background: var(--failed);
      box-shadow: 0 0 0 4px rgba(255, 125, 115, 0.10);
    }

    .resource-card:hover {
      transform: translateY(-3px);
      border-color: var(--line-strong);
      background:
        linear-gradient(180deg, rgba(255,255,255,0.07), rgba(255,255,255,0.03)),
        var(--card-2);
      box-shadow: 0 18px 34px rgba(0, 0, 0, 0.24);
    }

    .resource-top {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
      margin-bottom: 12px;
      padding-left: 18px;
    }

    .resource-domain {
      min-width: 0;
      overflow: hidden;
      color: #e8dfcf;
      font-family: var(--mono);
      font-size: 13px;
      font-weight: 900;
      text-overflow: ellipsis;
      white-space: nowrap;
    }

    .resource-open {
      flex: 0 0 auto;
      color: var(--accent);
      font-family: var(--mono);
      font-size: 11px;
      font-weight: 900;
      letter-spacing: 0;
      text-transform: uppercase;
    }

    .resource-meta {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 7px;
      margin-bottom: 12px;
    }

    .platform-badge,
    .resource-score,
    .pricing-chip {
      display: inline-flex;
      align-items: center;
      min-height: 28px;
      padding: 0 10px;
      border: 1px solid transparent;
      border-radius: 999px;
      font-family: var(--mono);
      font-size: 11px;
      font-weight: 900;
      letter-spacing: 0;
    }

    .platform-badge.is-newapi {
      color: #d7e5ff;
      background: rgba(120, 169, 255, 0.14);
      border-color: rgba(120, 169, 255, 0.24);
    }

    .platform-badge.is-favorite {
      color: #fff0c9;
      background: rgba(217, 164, 65, 0.16);
      border-color: rgba(217, 164, 65, 0.30);
    }

    .platform-badge.is-sub2 {
      color: #d9fff2;
      background: rgba(88, 208, 167, 0.13);
      border-color: rgba(88, 208, 167, 0.22);
    }

    .platform-badge.is-other {
      color: #e7ecef;
      background: rgba(154, 166, 184, 0.11);
      border-color: rgba(154, 166, 184, 0.18);
    }

    .platform-badge.is-review {
      color: #fff0d2;
      background: rgba(244, 184, 96, 0.14);
      border-color: rgba(244, 184, 96, 0.22);
    }

    .platform-badge.is-failed {
      color: #ffe0dc;
      background: rgba(255, 125, 115, 0.14);
      border-color: rgba(255, 125, 115, 0.22);
    }

    .assessment-chip {
      display: inline-flex;
      align-items: center;
      min-height: 28px;
      padding: 0 10px;
      border: 1px solid var(--line);
      border-radius: 999px;
      font-family: var(--mono);
      font-size: 11px;
      font-weight: 900;
      letter-spacing: 0;
      background: rgba(255,255,255,0.04);
      color: var(--muted);
    }

    .assessment-chip.is-trust-high {
      color: #ddfff6;
      background: rgba(49, 208, 170, 0.14);
      border-color: rgba(49, 208, 170, 0.22);
    }

    .assessment-chip.is-trust-mid {
      color: #dce8ff;
      background: rgba(120, 169, 255, 0.14);
      border-color: rgba(120, 169, 255, 0.22);
    }

    .assessment-chip.is-trust-low {
      color: #fff2d5;
      background: rgba(244, 184, 96, 0.14);
      border-color: rgba(244, 184, 96, 0.22);
    }

    .assessment-chip.is-trust-risk,
    .assessment-chip.is-risk {
      color: #ffdcd8;
      background: rgba(255, 125, 115, 0.12);
      border-color: rgba(255, 125, 115, 0.2);
    }

    .assessment-chip.is-entry {
      color: #e8dfcf;
      background: rgba(255,255,255,0.06);
      border-color: rgba(255,255,255,0.12);
    }

    .resource-section[data-group="我的常用"] .section-head {
      background: linear-gradient(90deg, rgba(217, 164, 65, 0.16), transparent 48%);
    }

    .resource-section[data-group="我的常用"] {
      border-color: rgba(217, 164, 65, 0.30);
      box-shadow:
        0 22px 54px rgba(0, 0, 0, 0.26),
        0 0 0 1px rgba(217, 164, 65, 0.06) inset;
    }

    .resource-section[data-group="我的常用"] .section-copy h2 {
      color: #ffe3a8;
    }

    .resource-section[data-group="公益站"] .section-head {
      background: linear-gradient(90deg, rgba(244, 184, 96, 0.16), transparent 48%);
    }

    .resource-score,
    .pricing-chip {
      color: var(--muted);
      background: rgba(255,255,255,0.05);
      border-color: var(--line);
    }

    .pricing-chip.-hot {
      color: #ffd5c5;
      background: rgba(255, 125, 115, 0.12);
      border-color: rgba(255, 125, 115, 0.18);
    }

    .pricing-chip.-cool {
      color: #d7e5ff;
      background: rgba(120, 169, 255, 0.12);
      border-color: rgba(120, 169, 255, 0.18);
    }

    .pricing-chip.-mint {
      color: #d9fff2;
      background: rgba(88, 208, 167, 0.12);
      border-color: rgba(88, 208, 167, 0.18);
    }

    .resource-card strong {
      display: block;
      margin: 0 0 12px;
      color: var(--text);
      font-size: 18px;
      font-weight: 850;
      line-height: 1.4;
      word-break: break-word;
    }

    .resource-url,
    .pricing-summary__meta,
    .resource-reason {
      color: var(--muted);
      font-family: var(--mono);
      font-size: 12px;
      line-height: 1.6;
      word-break: break-word;
    }

    .resource-url {
      word-break: break-all;
    }

    .resource-reason,
    .pricing-summary {
      display: block;
      margin-top: 12px;
      padding-top: 12px;
      border-top: 1px dashed var(--line-strong);
    }

    .resource-reason {
      color: #9ee9d3;
    }

    .pricing-summary {
      display: grid;
      gap: 8px;
    }

    .pricing-summary__top {
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
    }

    .empty-state {
      display: none;
      padding: 28px;
      border: 1px dashed var(--line-strong);
      border-radius: 18px;
      background: rgba(17, 20, 24, 0.92);
      color: var(--muted);
      text-align: center;
      box-shadow: none;
    }

    .empty-state.visible {
      display: block;
    }

    .calculator-panel {
      margin-bottom: 16px;
      overflow: hidden;
    }

    .calculator-head {
      padding: 18px 20px 14px;
      border-bottom: 1px solid var(--line);
      background: linear-gradient(90deg, rgba(217, 164, 65, 0.08), transparent 40%);
    }

    .calculator-head h2 {
      margin: 0;
      color: var(--text);
      font-family: var(--display);
      font-size: 26px;
      font-weight: 850;
      line-height: 1.08;
    }

    .calculator-head p {
      margin: 8px 0 0;
      color: var(--muted);
      font-size: 14px;
      line-height: 1.65;
    }

    .calculator-body {
      display: grid;
      gap: 14px;
      padding: 16px;
    }

    .calculator-grid,
    .ratio-grid,
    .result-grid {
      display: grid;
      gap: 12px;
    }

    .calculator-grid {
      grid-template-columns: repeat(4, minmax(0, 1fr));
    }

    .ratio-grid {
      grid-template-columns: repeat(3, minmax(0, 1fr));
    }

    .result-grid {
      grid-template-columns: repeat(4, minmax(0, 1fr));
    }

    .field,
    .result-card {
      border: 1px solid var(--line);
      border-radius: 16px;
      background: rgba(255,255,255,0.05);
    }

    .field {
      padding: 12px;
    }

    .field label,
    .result-card span {
      display: block;
      color: var(--subtle);
      font-family: var(--mono);
      font-size: 11px;
      font-weight: 900;
      letter-spacing: 0;
      text-transform: uppercase;
    }

    .field input,
    .field select {
      width: 100%;
      margin-top: 8px;
      min-height: 42px;
      border-radius: 12px;
      padding: 0 12px;
      outline: 0;
      font: inherit;
    }

    .result-card {
      padding: 14px;
      min-height: 92px;
      display: grid;
      align-content: start;
      gap: 8px;
    }

    .result-card strong {
      color: var(--text);
      font-family: var(--mono);
      font-size: 28px;
      font-weight: 900;
      line-height: 1.05;
      letter-spacing: 0;
      word-break: break-word;
    }

    .calculator-actions {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      align-items: center;
    }

    @media (max-width: 1180px) {
      .calculator-grid,
      .result-grid {
        grid-template-columns: repeat(2, minmax(0, 1fr));
      }
    }

    @media (max-width: 1080px) {
      .masthead,
      .control-bar {
        grid-template-columns: 1fr;
      }

      .control-bar {
        position: static;
      }
    }

    @media (max-width: 720px) {
      .page {
        width: min(100vw - 16px, 1540px);
        padding: 10px 0 28px;
      }

      .observatory-nav {
        gap: 6px;
      }

      .masthead {
        min-height: 0;
        padding: 18px;
      }

      .masthead h1 {
        font-size: 42px;
      }

      .meta-pill,
      .quick-chip,
      .observatory-nav a {
        width: 100%;
        justify-content: space-between;
      }

      .section-head {
        display: grid;
      }

      .resource-grid,
      .calculator-grid,
      .ratio-grid,
      .result-grid {
        grid-template-columns: 1fr;
      }

      .resource-card {
        min-height: 0;
      }
    }

    @media (prefers-reduced-motion: reduce) {
      *,
      *::before,
      *::after {
        scroll-behavior: auto !important;
        transition-duration: 0.01ms !important;
        animation-duration: 0.01ms !important;
      }
    }
    """
    nav_html = """
    <nav class="observatory-nav" aria-label="section navigation">
      <a class="is-live" href="#overview">总览</a>
      <a href="#pricingCalculator">算一笔账</a>
      <a href="#sectionStack">节点名册</a>
      <a href="#sectionStack">扫描台</a>
      <a href="#sectionStack">风险记录</a>
    </nav>
    """
    html_doc = re.sub(r"<style>.*?</style>", f"<style>{observatory_css}</style>", html_doc, count=1, flags=re.DOTALL)
    html_doc = html_doc.replace('<main class="page">', f'<main class="page" id="overview">\n    {nav_html}', 1)
    html_doc = re.sub(r"<title>.*?</title>", "<title>中转站生死簿 | RelayRadar Observatory</title>", html_doc, count=1, flags=re.DOTALL)
    html_doc = re.sub(r"<h1>.*?</h1>", "<h1>中转站生死簿</h1>", html_doc, count=1, flags=re.DOTALL)
    html_doc = re.sub(
        r"<p>.*?</p>",
        "<p>收编中转站，记录生死，验模型与计费。我们把这些节点做成一份可筛、可算、可复核的本地观测名册。</p>",
        html_doc,
        count=1,
        flags=re.DOTALL,
    )
    html_doc = html_doc.replace("Relay Dock", "RelayRadar Observatory")
    html_doc = html_doc.replace("Search / Filter", "扫描台")
    html_doc = html_doc.replace("Quota Calculator", "算一笔账")
    return html_doc


_bookmark_collection_renderer = render_spotlight_html


def render_spotlight_html(rows: list[dict], source_name: str) -> str:
    html_doc = _bookmark_collection_renderer(rows, source_name)
    html_doc = re.sub(
        r'\s*<section class="favorite-hero" aria-label=".*?">.*?</section>\s*',
        "\n",
        html_doc,
        count=1,
        flags=re.DOTALL,
    )
    html_doc = re.sub(
        r'\s*<section class="calculator-panel" id="pricingCalculator">.*?</section>\s*(?=<section id="sectionStack" class="stack">)',
        "\n    ",
        html_doc,
        count=1,
        flags=re.DOTALL,
    )
    html_doc = re.sub(
        r'\s*<script>\s*\(\(\)\s*=>\s*\{\s*const STORAGE_KEY = [\'"]relay_pricing_profiles_v1[\'"].*?</script>\s*',
        "\n",
        html_doc,
        count=1,
        flags=re.DOTALL,
    )
    html_doc = re.sub(r'\s*<a href="#pricingCalculator">.*?</a>', "", html_doc, count=1, flags=re.DOTALL)
    html_doc = re.sub(r'<div class="pricing-summary".*?</div>\s*</div>', "</div>", html_doc, flags=re.DOTALL)
    html_doc = re.sub(r'\s*\.pricing-summary__meta,\s*', "\n    ", html_doc, count=1)
    html_doc = re.sub(r'\s*\.pricing-summary\s*\{.*?\}\s*', "\n", html_doc, flags=re.DOTALL)
    html_doc = re.sub(r'\s*\.pricing-summary__top\s*\{.*?\}\s*', "\n", html_doc, flags=re.DOTALL)
    html_doc = re.sub(r"<title>.*?</title>", "<title>AI 中转站收藏导航</title>", html_doc, count=1, flags=re.DOTALL)
    html_doc = re.sub(r"<h1>.*?</h1>", "<h1>AI 中转站收藏导航</h1>", html_doc, count=1, flags=re.DOTALL)
    html_doc = re.sub(
        r"<p>.*?</p>",
        "<p>把常用中转站整理成一个清爽的私人收藏页，方便快速搜索、筛选和直接访问。</p>",
        html_doc,
        count=1,
        flags=re.DOTALL,
    )
    favorite_css = r"""
    .resource-section[data-group="我的常用"] {
      position: relative;
      overflow: hidden;
      border-color: rgba(255, 194, 92, 0.34);
      background:
        radial-gradient(circle at 10% 18%, rgba(255, 194, 92, 0.14), transparent 22%),
        radial-gradient(circle at 86% 18%, rgba(77, 163, 255, 0.10), transparent 20%),
        linear-gradient(135deg, rgba(25, 20, 12, 0.96), rgba(13, 17, 22, 0.96));
      box-shadow:
        0 26px 64px rgba(0, 0, 0, 0.34),
        0 0 0 1px rgba(255, 194, 92, 0.06) inset;
    }

    .resource-section[data-group="我的常用"]::before {
      content: "";
      position: absolute;
      inset: 0;
      pointer-events: none;
      background:
        linear-gradient(120deg, transparent 0%, rgba(255, 225, 155, 0.08) 36%, transparent 62%),
        repeating-linear-gradient(90deg, transparent 0 39px, rgba(255,255,255,0.018) 39px 40px);
      mask-image: linear-gradient(180deg, rgba(0,0,0,0.95), rgba(0,0,0,0.75));
    }

    .resource-section[data-group="我的常用"] .section-head {
      position: relative;
      background: linear-gradient(90deg, rgba(255, 194, 92, 0.16), transparent 52%);
    }

    .resource-section[data-group="我的常用"] .section-copy h2 {
      color: #ffe3a7;
      text-shadow: 0 0 24px rgba(255, 194, 92, 0.12);
    }

    .resource-section[data-group="我的常用"] .resource-card {
      overflow: hidden;
      border-color: rgba(255, 194, 92, 0.24);
      background:
        linear-gradient(180deg, rgba(255, 194, 92, 0.10), rgba(255,255,255,0.02)),
        rgba(24, 26, 31, 0.96);
      box-shadow:
        0 20px 38px rgba(0, 0, 0, 0.22),
        0 0 0 1px rgba(255, 194, 92, 0.05) inset;
      transition: transform 220ms ease, box-shadow 220ms ease, border-color 220ms ease;
    }

    .resource-section[data-group="我的常用"] .resource-card::after {
      content: "";
      position: absolute;
      inset: -28% auto auto -34%;
      width: 58%;
      height: 220%;
      transform: rotate(22deg);
      background: linear-gradient(90deg, transparent, rgba(255, 226, 154, 0.16), transparent);
      pointer-events: none;
    }

    .resource-section[data-group="我的常用"] .resource-card:hover {
      transform: translateY(-7px) scale(1.01);
      border-color: rgba(255, 194, 92, 0.42);
      box-shadow:
        0 28px 58px rgba(0, 0, 0, 0.28),
        0 0 30px rgba(255, 194, 92, 0.10);
    }

    .resource-section[data-group="我的常用"] .resource-card[data-favorite-tone="0"] {
      background:
        radial-gradient(circle at 86% 18%, rgba(82, 162, 255, 0.14), transparent 18%),
        linear-gradient(180deg, rgba(255, 194, 92, 0.10), rgba(255,255,255,0.02)),
        rgba(24, 26, 31, 0.96);
    }

    .resource-section[data-group="我的常用"] .resource-card[data-favorite-tone="1"] {
      background:
        radial-gradient(circle at 84% 18%, rgba(85, 226, 187, 0.14), transparent 18%),
        linear-gradient(180deg, rgba(255, 194, 92, 0.10), rgba(255,255,255,0.02)),
        rgba(24, 26, 31, 0.96);
    }

    .resource-section[data-group="我的常用"] .resource-card[data-favorite-tone="2"] {
      background:
        radial-gradient(circle at 84% 18%, rgba(255, 116, 133, 0.16), transparent 18%),
        linear-gradient(180deg, rgba(255, 194, 92, 0.10), rgba(255,255,255,0.02)),
        rgba(24, 26, 31, 0.96);
    }

    .resource-section[data-group="我的常用"] .resource-card[data-favorite-tone="3"] {
      background:
        radial-gradient(circle at 84% 18%, rgba(190, 129, 255, 0.16), transparent 18%),
        linear-gradient(180deg, rgba(255, 194, 92, 0.10), rgba(255,255,255,0.02)),
        rgba(24, 26, 31, 0.96);
    }
    """
    html_doc = html_doc.replace("</style>", favorite_css + "\n  </style>", 1)
    html_doc = html_doc.replace('<a class="resource-card" href="https://www.codex2api.com/keys"', '<a class="resource-card" data-favorite-tone="0" href="https://www.codex2api.com/keys"', 1)
    html_doc = html_doc.replace('<a class="resource-card" href="https://zhuozaiya.top/dashboard"', '<a class="resource-card" data-favorite-tone="1" href="https://zhuozaiya.top/dashboard"', 1)
    html_doc = html_doc.replace('<a class="resource-card" href="https://openai945.cn/recharge"', '<a class="resource-card" data-favorite-tone="2" href="https://openai945.cn/recharge"', 1)
    html_doc = html_doc.replace('<a class="resource-card" href="https://aklhaode199.xyz/subscriptions"', '<a class="resource-card" data-favorite-tone="3" href="https://aklhaode199.xyz/subscriptions"', 1)
    html_doc = html_doc.replace("RelayRadar Observatory", "AI Relay Bookmark Deck")
    html_doc = html_doc.replace("Overview", "Start")
    html_doc = html_doc.replace("All Bookmarks", "Bookmarks")
    html_doc = html_doc.replace("Quick Filter", "Filter")
    html_doc = html_doc.replace("Collections", "Collection")
    html_doc = re.sub(r'<button class="quick-chip" type="button" data-chip="探测失败".*?</button>', "", html_doc, flags=re.DOTALL)
    html_doc = re.sub(r'\s*<section class="resource-section" data-group="探测失败">.*?</section>\s*', "\n", html_doc, flags=re.DOTALL)
    html_doc = html_doc.replace("分布在 8 个分组", "分布在 7 个分组")
    return html_doc


def export_folder_html(bookmarks_data: dict, folder_name: str, output_path: Path, community_only: bool = False) -> Path:
    match = find_folder_by_name(bookmarks_data, folder_name)
    if not match:
        raise ValueError(f"没有找到文件夹: {folder_name}")
    path, folder = match
    rows = flatten_children(folder.get("children", []), path)
    if community_only:
        rows = filter_rows_to_community(rows)
    if folder_name.casefold() == "ai中转站".casefold() and not community_only:
        rows = enrich_rows_with_fingerprints(rows)
        rows = filter_rows_to_ai_relays(rows)
        rows = filter_out_failed_rows(rows)
        rows = [row for row in rows if not is_manually_excluded_domain(row.get("domain", ""))]
        existing_urls = {row.get("url", "") for row in rows}
        for pinned_row in MANUAL_PINNED_LINKS:
            if pinned_row["url"] not in existing_urls:
                rows.append(dict(pinned_row))
                existing_urls.add(pinned_row["url"])
        for extra_row in MANUAL_EXTRA_RELAY_LINKS:
            if extra_row["url"] not in existing_urls:
                rows.append(dict(extra_row))
                existing_urls.add(extra_row["url"])
        rows = dedupe_relay_rows(rows)
        rows = [{**row, "assessment": build_relay_assessment(row)} for row in rows]
    output_path.parent.mkdir(parents=True, exist_ok=True)
    page_name = " / ".join(path) + (" / 社区" if community_only else "")
    html_content = render_spotlight_html(rows, page_name)
    output_path.write_text(html_content, encoding="utf-8")
    return output_path


def parse_args() -> argparse.Namespace:
    default_bookmarks = Path(os.environ["LOCALAPPDATA"]) / "Google" / "Chrome" / "User Data" / "Default" / "Bookmarks"
    default_html = Path.cwd() / "chrome_bookmarks_dashboard.html"
    parser = argparse.ArgumentParser(
        description="分类整理 Chrome 书签，并可导出为本地网页。"
    )
    parser.add_argument(
        "--bookmarks-file",
        type=Path,
        default=default_bookmarks,
        help=f"Chrome Bookmarks 文件路径，默认是 {default_bookmarks}",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="真正写回书签文件。建议先关闭 Chrome。",
    )
    parser.add_argument(
        "--backup-dir",
        type=Path,
        default=Path.cwd() / "bookmark_backups",
        help="备份目录。",
    )
    parser.add_argument(
        "--keep",
        action="append",
        default=[],
        help="保留在顶栏不移动的书签名称，可重复传入多次。",
    )
    parser.add_argument(
        "--archive-folder",
        default=DEFAULT_ARCHIVE_FOLDER,
        help="现有文件夹统一收纳到哪个分组里。",
    )
    parser.add_argument(
        "--export-html",
        action="store_true",
        help="导出书签导航网页。",
    )
    parser.add_argument(
        "--html-output",
        type=Path,
        default=default_html,
        help=f"导出的网页路径，默认是 {default_html}",
    )
    parser.add_argument(
        "--folder-name",
        help="只导出指定文件夹，例如 ai中转站。",
    )
    parser.add_argument(
        "--community-only",
        action="store_true",
        help="只保留社区、文档、论坛、GitHub、Discord 这类链接。",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    bookmarks_path: Path = args.bookmarks_file
    if not bookmarks_path.exists():
        print(f"找不到书签文件: {bookmarks_path}", file=sys.stderr)
        return 1

    data = load_bookmarks(bookmarks_path)
    bar_children = list(data["roots"]["bookmark_bar"].get("children", []))
    keep_names = set(DEFAULT_KEEP_NAMES)
    keep_names.update(item for item in args.keep if item)
    organized, grouped = organize_bookmark_bar(data, keep_names, args.archive_folder)

    print_preview(bar_children, grouped, keep_names, args.archive_folder)
    print("")

    if args.export_html:
        if args.folder_name:
            output_path = export_folder_html(
                organized,
                args.folder_name,
                args.html_output,
                community_only=args.community_only,
            )
        else:
            output_path = export_html(organized, args.html_output)
        print(f"网页导航已生成: {output_path}")

    if not args.apply:
        print("当前为预览模式，未修改任何书签文件。")
        print("如果想应用分类结果，可执行:")
        print(f'  python "{Path(__file__).name}" --apply')
        return 0

    backup_path = backup_bookmarks(bookmarks_path, args.backup_dir)
    write_bookmarks(bookmarks_path, organized)
    print(f"已写回书签文件: {bookmarks_path}")
    print(f"备份已保存到: {backup_path}")
    print("如果 Chrome 正在运行，建议重启浏览器后查看效果。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
