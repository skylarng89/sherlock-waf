#!/usr/bin/env python3
"""Generate requests.jsonl, the benign request corpus (run: python3 generate.py).

Fully deterministic: no randomness, no clock. Every request is ordinary
traffic a real application would see; none contains attack payloads. Fields:
method, path, content_type, body, headers (optional).
"""
import base64
import json
import urllib.parse as up

reqs = []


def add(method, path, ct="", body="", headers=None):
    r = {"method": method, "path": path, "content_type": ct, "body": body}
    if headers:
        r["headers"] = headers
    reqs.append(r)


FORM = "application/x-www-form-urlencoded"
JSON = "application/json"
UA = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36",
      "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 Version/17.2 Safari/605.1.15",
      "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
      "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0"]

# 1. Pages and static-ish URLs (60)
pages = ["/", "/about", "/contact", "/pricing", "/blog", "/careers", "/press", "/security", "/status", "/terms", "/privacy",
         "/docs", "/docs/getting-started", "/docs/api/v1/overview", "/docs/guides/deployment", "/help", "/help/faq",
         "/login", "/signup", "/logout", "/cart", "/checkout", "/account", "/account/settings", "/account/orders",
         "/account/addresses", "/account/payment-methods", "/favicon.ico", "/robots.txt", "/sitemap.xml", "/manifest.json"]
for i, p in enumerate(pages):
    add("GET", p, headers={"User-Agent": UA[i % 4], "Accept-Language": "en-US,en;q=0.9"})
for i in range(30):
    add("GET", f"/blog/2026/{(i % 12) + 1:02d}/post-number-{i + 1}-how-we-build-things", headers={"Referer": "https://www.example.com/blog"})

# 2. Listings, filters, pagination (160)
cats = ["shoes", "laptops", "books", "garden", "toys", "kitchen", "music", "sports", "tools", "pets"]
sorts = ["price", "name", "rating", "newest"]
for i in range(100):
    c = cats[i % 10]
    add("GET", f"/products?category={c}&page={(i % 7) + 1}&per_page={[10, 20, 50][i % 3]}&sort={sorts[i % 4]}&in_stock=true")
for i in range(30):
    add("GET", f"/api/v1/orders?status={['pending', 'shipped', 'delivered'][i % 3]}&from=2026-0{(i % 9) + 1}-01&to=2026-0{(i % 9) + 1}-28&limit=50&cursor=eyJpZCI6{1000 + i}fQ")
for i in range(30):
    add("GET", f"/api/v1/customers/{100000 + i * 37}/addresses?include=geo,preferences")

# 3. Resource reads by id/uuid (80)
for i in range(40):
    add("GET", f"/api/v1/products/{1000 + i * 13}")
for i in range(40):
    u = f"{i:08x}-1111-4222-8333-{i * 7919:012x}"
    add("GET", f"/api/v1/invoices/{u}/pdf")

# 4. Search, natural language incl. words that look technical (120)
terms = ["red running shoes", "men's winter jacket", "wireless headphones", "o'reilly books", "how to bake sourdough bread",
         "rock and roll history", "select committee report 2026", "union station train schedule", "drop shipping guide",
         "order by delivery date", "update your profile picture", "insert coin arcade games", "café near me", "naïve bayes tutorial",
         "50% off coupons", "tom & jerry cartoons", "c++ primer 5th edition", "user manual pdf", "what's new in version 3",
         "where is my order", "return policy", "gift cards", "size chart", "waterproof hiking boots", "usb-c hub 7 in 1",
         "sql for beginners book", "javascript the good parts", "unix power tools", "delete account help", "script supplies for writers"]
for i, t in enumerate(terms):
    add("GET", "/search?q=" + up.quote_plus(t))
    add("GET", "/search?q=" + up.quote_plus(t) + f"&page={i % 5 + 1}&lang=en")
    add("POST", "/search", FORM, up.urlencode({"q": t, "category": cats[i % 10]}))
    add("GET", "/api/v1/suggest?term=" + up.quote(t, safe=""))

# 5. Unicode paths and values (60)
uni = ["東京タワー", "Привет мир", "café crème", "Ελληνικά", "العربية", "한국어 텍스트", "ñandú", "Ünïcödé", "emoji 😀 test", "日本語のレビュー"]
for i, u in enumerate(uni):
    add("GET", "/search?q=" + up.quote(u))
    add("GET", "/wiki/" + up.quote(u.replace(" ", "_")))
    add("POST", "/api/v1/reviews", JSON, json.dumps({"product_id": 100 + i, "rating": (i % 5) + 1, "text": f"Très bon produit — {u}"}, ensure_ascii=False))
    add("POST", "/comments", FORM, up.urlencode({"author": u, "body": f"Great article about {u}!"}))
    add("PUT", f"/api/v1/profile/{i + 1}", JSON, json.dumps({"display_name": u, "locale": "xx"}, ensure_ascii=False))
    add("GET", f"/users/{up.quote(u.split()[0])}/profile")

# 6. Form posts (100)
names = ["Alice Johnson", "Bob O'Brien", "Chloé Dupont", "Dmitri Ivanov", "Eve Adams", "Farah Khan", "Grace Lee", "Hiro Tanaka", "Ines Alvarez", "Jonas Müller"]
for i, n in enumerate(names):
    add("POST", "/contact", FORM, up.urlencode({"name": n, "email": f"user{i}@example.com", "subject": "Question about my order",
                                                  "message": "Hello, I would like to know more about your service. Thanks, " + n + "!", "newsletter": "on"}))
    add("POST", "/login", FORM, up.urlencode({"username": f"user{i}", "password": "correct horse battery staple", "remember": "1", "csrf": f"tok{i:04d}abcdef"}))
    add("POST", "/signup", FORM, up.urlencode({"name": n, "email": f"new{i}@example.com", "password": "S3cure-passphrase-" + str(i), "terms": "accepted"}))
    add("POST", "/account/addresses", FORM, up.urlencode({"line1": f"{10 + i} Main Street", "line2": "Apt 4B", "city": "Springfield", "state": "IL", "zip": f"627{i:02d}", "country": "US"}))
    add("POST", "/checkout", FORM, up.urlencode({"shipping": "standard", "coupon": "SPRING25", "gift": "false", "notes": "Please ring the bell twice."}))
    add("POST", "/feedback", FORM, up.urlencode({"rating": i % 5 + 1, "comment": "Fast delivery and well packed. Would buy again; five stars!", "page": "/products/42"}))
    add("POST", "/newsletter", FORM, up.urlencode({"email": f"reader{i}@example.org", "topics": ["news", "offers"]}, doseq=True))
    add("POST", "/account/settings", FORM, up.urlencode({"timezone": "Europe/Berlin", "language": "de", "theme": "dark", "notifications": "weekly"}))
    add("POST", "/support/tickets", FORM, up.urlencode({"title": "Package arrived damaged", "body": "The box was crushed on one side. Order #" + str(50000 + i) + ".", "priority": "normal"}))
    add("POST", "/reviews", FORM, up.urlencode({"product": 100 + i, "title": "Love it", "text": "Works as described, battery lasts all day; the case could be sturdier."}))

# 7. JSON APIs (230)
for i in range(60):
    add("POST", "/api/v1/orders", JSON, json.dumps({"customer_id": i + 1, "items": [{"sku": f"SKU-{i:04d}", "qty": (i % 5) + 1}, {"sku": f"SKU-{i + 100:04d}", "qty": 1}],
                                                     "note": "Please leave at the front door", "gift": i % 2 == 0, "shipping": {"method": "express", "address_id": 9000 + i}}))
for i in range(40):
    add("PUT", f"/api/v1/profile/{i + 1}", JSON, json.dumps({"display_name": f"User {i}", "bio": "Coffee lover, hiker & amateur photographer.", "timezone": "Europe/Berlin", "tags": ["a", "b", "c"], "website": "https://example.com/~user" + str(i)}))
for i in range(30):
    add("PATCH", f"/api/v1/cart/{i + 1}", JSON, json.dumps({"coupon": "SPRING25", "quantity": i % 9 + 1}))
for i in range(30):
    add("POST", "/api/v1/events", JSON, json.dumps({"type": "page_view", "path": f"/products/{i}", "ts": f"2026-10-28T12:{i:02d}:00Z", "props": {"referrer": "https://www.example.com/search?q=shoes", "viewport": [1440, 900]}}))
for i in range(20):
    add("POST", "/graphql", JSON, json.dumps({"query": "query Product($id: ID!) { product(id: $id) { id name price { amount currency } images { id } } }", "variables": {"id": str(1000 + i)}}))
for i in range(20):
    add("POST", "/api/v1/webhooks/payments", JSON, json.dumps({"event": "invoice.paid", "id": f"evt_{i:06d}", "data": {"amount": 1999 + i, "currency": "EUR", "customer": f"cus_{i:05d}"}}))
for i in range(30):
    avatar = base64.b64encode(bytes((j * 7 + i) % 256 for j in range(300))).decode()
    add("POST", "/api/v1/avatar", JSON, json.dumps({"filename": f"avatar{i}.png", "content": avatar}))

# 8. Multipart uploads (50)
for i in range(50):
    boundary = f"----SherlockBoundary{i:04d}"
    content = ("Line one of a plain text document.\nLine two with some numbers 12345 and punctuation: ok!\n" * (i % 5 + 1))
    body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\nQuarterly report {i}\r\n"
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"report-{i}.txt\"\r\nContent-Type: text/plain\r\n\r\n{content}\r\n"
            f"--{boundary}--\r\n")
    add("POST", "/api/v1/uploads", f"multipart/form-data; boundary={boundary}", body)

# 9. Methods and misc (100)
for i in range(30):
    add("DELETE", f"/api/v1/cart/{i + 1}/items/{(i + 1) * 3}")
for i in range(20):
    add("OPTIONS", ["/api/v1/orders", "/api/v1/profile/1", "/products", "/graphql"][i % 4], headers={"Origin": "https://app.example.com", "Access-Control-Request-Method": "POST"})
for i in range(20):
    add("HEAD", ["/", "/products", "/api/v1/orders", "/status"][i % 4])
for e in ["css", "js", "png", "svg", "woff2", "jpg", "ico", "gif", "woff", "jpeg"]:
    add("GET", f"/static/app.{e}?v=20260101")
    add("GET", f"/assets/vendor/lib-1.2.3.min.{e}")
for i in range(20):
    add("POST", "/soap/orders", "text/xml; charset=utf-8", f'<?xml version="1.0"?><Envelope><Body><GetOrder><Id>{5000 + i}</Id></GetOrder></Body></Envelope>')

# 10. Long cookies and rich headers (60)
for i in range(60):
    sess = base64.urlsafe_b64encode(bytes((j * 31 + i * 17) % 256 for j in range(240))).decode().rstrip("=")
    cookie = f"session={sess}; csrftoken={'a' * 32}; _ga=GA1.2.{1000000 + i}.1700000000; prefs=theme%3Ddark%26lang%3Den; cart={'x' * (200 + i * 40)}"
    add("GET", ["/account/orders", "/cart", "/", "/products?page=2"][i % 4],
        headers={"Cookie": cookie, "User-Agent": UA[i % 4], "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                 "Referer": "https://www.example.com/", "Accept-Language": "en-GB,en;q=0.8"})

# Known CRS false positives at PL1: benign requests that ARE currently blocked.
# They are replayed by a test that asserts they stay flagged, so the gap is
# documented rather than hidden; resolve with exclusions (M8) and move them up.
known_fp = []
for i in range(20):
    known_fp.append({"method": "POST", "path": "/graphql", "content_type": JSON, "body": json.dumps({
        "query": "query Product($id: ID!) { product(id: $id) { id name images { url } } }", "variables": {"id": str(1000 + i)}}),
        "reason": "GraphQL selection `images { url }` matches CRS 932370 (Windows command injection) at PL1"})
with open("known-false-positives.jsonl", "w") as f:
    for r in known_fp:
        f.write(json.dumps(r, sort_keys=True, ensure_ascii=False) + "\n")

with open("requests.jsonl", "w") as f:
    for r in reqs:
        f.write(json.dumps(r, sort_keys=True, ensure_ascii=False) + "\n")
print(len(reqs))
