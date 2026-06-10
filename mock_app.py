"""Mock login server to test userenum. Three endpoints:
  /login  - clean: valid users get a clearly longer message
  /noisy  - every response gets random padding (jitter); valid users +80 bytes
  /subtle - valid/invalid differ by only ~3 bytes, hidden under jitter (should NOT flag)
"""
import random
from flask import Flask, request

app = Flask(__name__)
VALID = {"admin", "rdw", "john.smith", "support"}


@app.route("/login", methods=["POST"])
def login():
    u = request.form.get("username", "")
    if u in VALID:
        return ("Login failed. The password you entered for this account is "
                "incorrect. Please try again or reset your password."), 200
    return "Login failed. Unknown user.", 200


@app.route("/noisy", methods=["POST"])
def noisy():
    u = request.form.get("username", "")
    pad = "x" * random.randint(0, 12)          # jitter on every response
    base = "Login failed. Please check your credentials and try again." + pad
    if u in VALID:
        base += "y" * 80                        # real signal, well above jitter
    return base, 200


@app.route("/subtle", methods=["POST"])
def subtle():
    u = request.form.get("username", "")
    pad = "x" * random.randint(0, 12)
    base = "Login failed." + pad
    if u in VALID:
        base += "yyy"                           # only 3 bytes, lost in jitter
    return base, 200


if __name__ == "__main__":
    app.run(port=5001)
