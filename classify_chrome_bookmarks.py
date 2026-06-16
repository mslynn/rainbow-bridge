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
        "深度识别为 NewAPI",
        "深度识别为 Sub2API",
        "非这两类",
        "待人工确认",
        "探测失败",
    ]
    platform_group_meta = {
        "深度识别为 NewAPI": "命中 NewAPI 公开接口或前端强指纹，优先可直接用。",
        "深度识别为 Sub2API": "命中 Sub2API 公开接口或前端强指纹，优先可直接筛。",
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
        if "NewAPI" in label:
            return "is-newapi"
        if "Sub2API" in label or "Sub2" in label:
            return "is-sub2"
        if label == "非这两类":
            return "is-other"
        if label == "待人工确认":
            return "is-review"
        return "is-failed"

    def classify_resource(row: dict) -> str:
        combined = f"{row['title']} {row['url']} {row['domain']}".lower()
        path = urlparse(row["url"]).path.lower()
        fingerprint = row.get("fingerprint", {})
        platform = normalize_platform_label(fingerprint.get("platform"))

        if ai_relay_mode:
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
                meta_html = (
                    f'<div class="resource-meta">'
                    f'<span class="platform-badge {badge_class(label)}">{html.escape(label)}</span>'
                    f"{score_html}"
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
        sections.append(
            f"""
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
        )

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
