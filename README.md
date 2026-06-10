# userenum

## Install

```
git clone https://github.com/rdwsec/userenum.git
cd userenum
pip install -r requirements.txt
```

Requires Python 3.

## Usage

Basic:

```
python userenum.py -u https://target/login -w usernames.txt
```

With a SecLists wordlist and a polite delay:

```
python userenum.py -u https://target/login \
  -w /usr/share/seclists/Usernames/top-usernames-shortlist.txt \
  --delay 0.3 --insecure
```

Common options:

- `-u` target login URL
- `-w` username wordlist, one per line
- `-p` fixed wrong password (defaults to a long random one)
- `--username-field` / `--password-field` form field names if not `username` / `password`
- `-t json` for JSON APIs instead of form data
- `--csrf-url` / `--csrf-field` to pull and resend a CSRF token
- `--baseline` number of garbage samples used to learn the band (raise it on noisy apps)
- `--sigma` how far outside the baseline counts as a hit (lower = more aggressive)
- `--delay` / `--threads` to control request rate
- `-o` save the candidate usernames to a file

Run `python userenum.py -h` for the full option list.

## Example output

```
[*] Learning invalid baseline with 12 garbage usernames...
[*] Baseline length: mean=62.4 stdev=3.3 -> normal band [53 .. 72]
[*] Testing 12 usernames ...

=== RESULTS ===
Tested: 12  |  Errors: 0  |  Likely-valid candidates: 4
Baseline mean=62.4, normal band [53 .. 72]

Likely-valid usernames (length outside baseline band):
  [+] admin       len=146 (delta +84) status=200
  [+] support     len=138 (delta +76) status=200
```

## Limitations and roadmap

v1 detects **length-based** enumeration only. Some applications don't leak via length — the signal may be in the status code, response timing, or error text instead. Planned:

- timing-based detection
- status-code based detection
- broader automatic CSRF handling

## Legal

For authorised security testing only. Run this against systems you own or have explicit written permission to test. The author accepts no responsibility for misuse.

## License

MIT
