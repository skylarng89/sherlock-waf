#!/usr/bin/env python3
"""Triage helper for the virtual-patching process (docs/security/virtual-patching-process.md).

  kev_triage.py triage   open one `vpatch-triage` issue per new web-relevant CISA KEV entry
  kev_triage.py verify   fail when a rule in rules/virtual-patches claims kev: true for a CVE
                         that the CISA catalogue does not list

Standard library only. `triage` needs the `gh` CLI and GH_TOKEN (the workflow
provides both); `--dry-run` prints what it would open and touches nothing.
The feed is data, never instructions: its text is only matched against keyword
lists and quoted inside a fenced block in the issue.
"""
import argparse
import datetime as dt
import json
import os
import re
import subprocess
import sys
import urllib.request

FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
LABEL = "vpatch-triage"
PACK = os.path.join(os.path.dirname(__file__), "..", "rules", "virtual-patches")

# Words that suggest the vulnerable software is reachable over HTTP.
WEB = [
    "web", "http", "portal", "api", "cms", "plugin", "gateway", "vpn", "servlet", "console", "management interface",
    "wordpress", "drupal", "joomla", "magento", "confluence", "jira", "atlassian", "bitbucket", "fortios", "fortinet", "fortiweb",
    "ivanti", "pulse secure", "citrix", "netscaler", "big-ip", "spring", "struts", "log4j", "tomcat", "weblogic", "jboss", "wildfly",
    "jenkins", "gitlab", "exchange", "sharepoint", "grafana", "zimbra", "roundcube", "moveit", "goanywhere", "papercut", "screenconnect",
    "manageengine", "sonicwall", "palo alto", "pan-os", "globalprotect", "cisco asa", "apache", "nginx", "iis", "php", "laravel", "django",
    "rails", "node.js", "teamcity", "vcenter", "solarwinds", "sap netweaver", "oracle e-business", "coldfusion", "openfire", "metabase",
]
# Software that is not served over HTTP; matched against vendor and product.
NOT_WEB = ["windows kernel", "win32k", "android", "macos", "ios ", "linux kernel", "chromium", "chrome", "firefox", "flash player",
           "office", "outlook", "internet explorer", "edge", "safari", "webkit", "adobe reader", "acrobat", "bluetooth", "hyper-v", "dwm core"]


def fetch_feed(path=None):
    if path:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    req = urllib.request.Request(FEED, headers={"User-Agent": "sherlock-waf-kev-triage"})
    with urllib.request.urlopen(req, timeout=60) as r:  # noqa: S310 - fixed https URL
        return json.load(r)


def web_relevant(entry):
    ident = f"{entry.get('vendorProject', '')} {entry.get('product', '')}".lower()
    text = f"{ident} {entry.get('vulnerabilityName', '')} {entry.get('shortDescription', '')}".lower()
    if any(n in ident for n in NOT_WEB):
        return False
    return any(re.search(r"(?<![a-z0-9])" + re.escape(w) + r"(?![a-z0-9])", text) for w in WEB)


def known_cves():
    """CVEs the pack already handles: rules and CRS coverage."""
    found = set()
    if not os.path.isdir(PACK):
        return found
    for name in os.listdir(PACK):
        if name.endswith((".yaml", ".yml")) and not name.endswith(".tests.yaml"):
            with open(os.path.join(PACK, name), encoding="utf-8") as f:
                found.update(re.findall(r"CVE-\d{4}-\d{4,}", f.read()))
    return found


def pack_kev_claims():
    """CVEs of rules that say kev: true."""
    claims = {}
    for name in sorted(os.listdir(PACK)):
        if not re.fullmatch(r"SV-\d{4}-\d{4}\.yaml", name):
            continue
        with open(os.path.join(PACK, name), encoding="utf-8") as f:
            meta = json.loads(re.sub(r"^#.*\n", "", f.read(), flags=re.M))  # metadata is JSON (valid YAML) after the comment header
        if meta.get("kev"):
            for cve in meta["cves"]:
                claims[cve] = meta["id"]
    return claims


def recent(entries, days, today=None):
    today = today or dt.date.today()
    cutoff = today - dt.timedelta(days=days)
    return [e for e in entries if dt.date.fromisoformat(e["dateAdded"]) >= cutoff]


def issue_body(e):
    fence = "```"
    desc = (e.get("shortDescription") or "").replace(fence, "'''")
    return "\n".join([
        f"New CISA KEV entry that looks web-facing. Triage within 2 business days (24 h if critical), per `docs/security/virtual-patching-process.md`.",
        "",
        f"- CVE: {e['cveID']}",
        f"- Vendor / product: {e.get('vendorProject', '?')} / {e.get('product', '?')}",
        f"- Added to KEV: {e['dateAdded']}  (due date {e.get('dueDate', '?')})",
        f"- Ransomware use: {e.get('knownRansomwareCampaignUse', 'Unknown')}",
        f"- NVD: https://nvd.nist.gov/vuln/detail/{e['cveID']}",
        "",
        "Catalogue text (untrusted data from the feed):",
        fence,
        f"{e.get('vulnerabilityName', '')}",
        desc,
        fence,
        "",
        "Decide one outcome and close the issue with a comment:",
        "- [ ] **Covered by CRS**: reproduce at PL1 with CRS only; if blocked, add it to `rules/virtual-patches/covered-by-crs.yaml` with the request",
        "- [ ] **Write rule**: narrowest match, `SV-<year>-<n>.conf/.yaml/.tests.yaml`, positive and negative tests, bypass review",
        "- [ ] **Out of scope**: not reachable over HTTP, no public details, or irrelevant to users (say why)",
    ])


def existing_titles():
    out = subprocess.run(["gh", "issue", "list", "--label", LABEL, "--state", "all", "--limit", "1000", "--json", "title"],
                         check=True, capture_output=True, text=True).stdout
    return " ".join(i["title"] for i in json.loads(out))


def triage(args):
    feed = fetch_feed(args.feed)
    candidates = [e for e in recent(feed["vulnerabilities"], args.days) if web_relevant(e) and e["cveID"] not in known_cves()]
    titles = "" if args.dry_run else existing_titles()
    opened = 0
    for e in sorted(candidates, key=lambda x: x["cveID"]):
        if e["cveID"] in titles:
            continue
        title = f"vpatch-triage: {e['cveID']} {e.get('vendorProject', '')} {e.get('product', '')}".strip()
        if args.dry_run:
            print(title)
            continue
        subprocess.run(["gh", "issue", "create", "--title", title[:200], "--label", LABEL, "--body", issue_body(e)], check=True)
        opened += 1
    print(f"{len(candidates)} candidate(s), {opened} issue(s) opened")
    return 0


def verify(args):
    listed = {e["cveID"] for e in fetch_feed(args.feed)["vulnerabilities"]}
    bad = {cve: sv for cve, sv in pack_kev_claims().items() if cve not in listed}
    for cve, sv in sorted(bad.items()):
        print(f"{sv}: claims kev: true but {cve} is not in the CISA KEV catalogue", file=sys.stderr)
    return 1 if bad else 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name, fn in (("triage", triage), ("verify", verify)):
        p = sub.add_parser(name)
        p.add_argument("--feed", help="read the feed from a file instead of CISA (tests)")
        if name == "triage":
            p.add_argument("--days", type=int, default=3, help="look back this many days (default 3; the workflow runs daily)")
            p.add_argument("--dry-run", action="store_true")
        p.set_defaults(fn=fn)
    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
