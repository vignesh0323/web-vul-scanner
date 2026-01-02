#!/usr/bin/env python3
"""
WebGuard Scanner — basic SQLi + XSS scanner
Author: Alahu Gopal M
"""
print(r'''
============================================
       WebGuard Scanner v1.0
  Use responsibly. Only test with permission.
============================================
''')
# (rest of your code follows)
"""
Web Vulnerability Scanner Tool
Single-file CLI tool that scans for basic SQL Injection and XSS vulnerabilities,
with optional crawling and report output (JSON/HTML).

Usage examples:
    python -m web_vuln_scanner --url https://example.com --scan all --crawl 1 --output report.json

Dependencies:
    pip install requests beautifulsoup4 tqdm

Author: Generated for CODTECH internship task-2
"""

import argparse
import json
import os
import queue
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Set

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from tqdm import tqdm

# --- Configuration / Payloads ---
SQLI_TESTS = ["' OR '1'='1", "' OR 1=1 --", '" OR "1"="1']
XSS_TESTS = ['<script>alert(1)</script>', '"\'><script>alert(1)</script>']
DEFAULT_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; WebVulnScanner/1.0)"}

# --- Helpers ---

def fetch(url: str, method: str = 'get', params=None, data=None, timeout=15):
    try:
        if method.lower() == 'get':
            return requests.get(url, params=params, headers=DEFAULT_HEADERS, timeout=timeout, allow_redirects=True)
        return requests.post(url, data=data, headers=DEFAULT_HEADERS, timeout=timeout)
    except requests.RequestException as e:
        return None


def get_forms_from_text(base_url: str, text: str):
    soup = BeautifulSoup(text, 'html.parser')
    forms = []
    for form in soup.find_all('form'):
        details = {
            'action': form.get('action') or '',
            'method': form.get('method', 'get').lower(),
            'inputs': []
        }
        for input_tag in form.find_all(['input', 'textarea', 'select']):
            input_type = input_tag.get('type', 'text')
            name = input_tag.get('name')
            if name:
                details['inputs'].append({'type': input_type, 'name': name})
        forms.append(details)
    return forms


def build_target_url(base: str, action: str):
    return urljoin(base, action)


# --- Scanner logic ---

def submit_form_and_check(url: str, form: Dict, payload: str):
    target = build_target_url(url, form['action'])
    data = {}
    for inp in form['inputs']:
        # insert payload into text-like fields, give default values for others
        if inp['type'] in ('text', 'search', 'email', 'url', 'textarea'):
            data[inp['name']] = payload
        else:
            data[inp['name']] = 'test'
    resp = fetch(target, method=form['method'], data=data)
    return resp


def scan_forms_for_sqli(url: str, forms: List[Dict]):
    results = []
    for form in forms:
        for payload in SQLI_TESTS:
            resp = submit_form_and_check(url, form, payload)
            if resp and resp.text:
                text = resp.text.lower()
                if any(err in text for err in ('sql syntax', 'mysql', 'syntax error', 'sqlstate', 'database error')):
                    results.append({'type': 'sqli', 'url': build_target_url(url, form['action']), 'payload': payload})
                    break
    return results


def scan_forms_for_xss(url: str, forms: List[Dict]):
    results = []
    for form in forms:
        for payload in XSS_TESTS:
            resp = submit_form_and_check(url, form, payload)
            if resp and payload in resp.text:
                results.append({'type': 'xss', 'url': build_target_url(url, form['action']), 'payload': payload})
                break
    return results


# --- Crawler ---

def extract_links(base_url: str, text: str) -> Set[str]:
    soup = BeautifulSoup(text, 'html.parser')
    anchors = set()
    parsed_base = urlparse(base_url)
    base_netloc = parsed_base.netloc
    for a in soup.find_all('a', href=True):
        href = a['href'].strip()
        if href.startswith('javascript:') or href.startswith('mailto:'):
            continue
        full = urljoin(base_url, href)
        parsed = urlparse(full)
        # stay within same domain
        if parsed.netloc == base_netloc:
            # normalize (remove fragment)
            anchors.add(parsed._replace(fragment='').geturl())
    return anchors


def crawl(start_url: str, max_depth: int = 1, max_pages: int = 50):
    visited = set()
    to_visit = queue.Queue()
    to_visit.put((start_url, 0))
    pages = []
    while not to_visit.empty() and len(visited) < max_pages:
        url, depth = to_visit.get()
        if url in visited:
            continue
        resp = fetch(url)
        visited.add(url)
        if not resp or not resp.text:
            continue
        pages.append({'url': url, 'text': resp.text})
        if depth < max_depth:
            links = extract_links(url, resp.text)
            for link in links:
                if link not in visited:
                    to_visit.put((link, depth + 1))
    return pages


# --- Orchestration ---

def scan_target(url: str, do_sqli: bool, do_xss: bool, crawl_depth: int, max_pages: int, workers: int):
    report = {'target': url, 'found': [], 'scanned_pages': []}

    pages = []
    if crawl_depth > 0:
        pages = crawl(url, max_depth=crawl_depth, max_pages=max_pages)
    else:
        resp = fetch(url)
        if resp and resp.text:
            pages = [{'url': url, 'text': resp.text}]

    # scan pages with thread pool
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {}
        for page in pages:
            forms = get_forms_from_text(page['url'], page['text'])
            report['scanned_pages'].append({'url': page['url'], 'forms': forms})
            # schedule scans
            if do_sqli:
                futures[ex.submit(scan_forms_for_sqli, page['url'], forms)] = page['url']
            if do_xss:
                futures[ex.submit(scan_forms_for_xss, page['url'], forms)] = page['url']

        for fut in tqdm(as_completed(futures), total=len(futures), desc='Scanning'):
            try:
                res = fut.result()
                if res:
                    report['found'].extend(res)
            except Exception as e:
                # ignore individual task failures
                pass

    return report


# --- Reporting ---

def save_report(report: Dict, path: str):
    ext = os.path.splitext(path)[1].lower()
    if ext == '.json' or ext == '':
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)
        return path
    elif ext == '.html':
        html = ['<html><head><meta charset="utf-8"><title>Scan Report</title></head><body>']
        html.append(f"<h1>Scan report for {report.get('target')}</h1>")
        html.append('<h2>Findings</h2>')
        if not report['found']:
            html.append('<p>No issues found.</p>')
        else:
            html.append('<ul>')
            for item in report['found']:
                html.append(f"<li>{item['type'].upper()} at {item['url']} — payload: {item['payload']}</li>")
            html.append('</ul>')
        html.append('<h2>Scanned pages</h2><ul>')
        for p in report['scanned_pages']:
            html.append(f"<li>{p['url']} — forms: {len(p['forms'])}</li>")
        html.append('</ul></body></html>')
        with open(path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(html))
        return path
    else:
        # default to json
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)
        return path


# --- CLI ---

def build_argparser():
    p = argparse.ArgumentParser(description='Simple Web Vulnerability Scanner (SQLi + XSS)')
    p.add_argument('--url', '-u', required=True, help='Target base URL (include http/https)')
    p.add_argument('--scan', choices=['sqli', 'xss', 'all'], default='all', help='Which checks to run')
    p.add_argument('--crawl', '-c', type=int, default=0, help='Crawl depth (0 = only URL, 1 = follow links one level)')
    p.add_argument('--max-pages', type=int, default=50, help='Max pages to crawl')
    p.add_argument('--workers', type=int, default=6, help='Concurrent worker threads')
    p.add_argument('--output', '-o', default='report.json', help='Output report file (json or html)')
    return p


def main_cli():
    parser = build_argparser()
    args = parser.parse_args()
    do_sqli = args.scan in ('sqli', 'all')
    do_xss = args.scan in ('xss', 'all')

    start = time.time()
    report = scan_target(args.url, do_sqli, do_xss, args.crawl, args.max_pages, args.workers)
    path = save_report(report, args.output)
    elapsed = time.time() - start
    print(f"Scan complete in {elapsed:.1f}s. Report saved to: {path}")


if __name__ == '__main__':
    main_cli()
