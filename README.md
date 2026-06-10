# userenum
Username enumeration tool that detects valid accounts

Install:

git clone https://github.com/rdwsec/userenum.git
cd userenum
pip install -r requirements.txt
Requires Python 3.
Usage
Basic:
python userenum.py -u https://target/login -w usernames.txt
With a SecLists wordlist and a polite delay:
python userenum.py -u https://target/login \
  -w /usr/share/seclists/Usernames/top-usernames-shortlist.txt \
  --delay 0.3 --insecure
Common options:

-u target login URL
-w username wordlist, one per line
-p fixed wrong password (defaults to a long random one)
--username-field / --password-field form field names if not username / password
-t json for JSON APIs instead of form data
--csrf-url / --csrf-field to pull and resend a CSRF token
--baseline number of garbage samples used to learn the band (raise it on noisy apps)
--sigma how far outside the baseline counts as a hit (lower = more aggressive)
--delay / --threads to control request rate
-o save the candidate usernames to a file

Run python userenum.py -h for the full option list.
