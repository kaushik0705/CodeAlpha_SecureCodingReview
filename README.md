# CodeAlpha_SecureCodingReview

This is my Task 3 project for the CodeAlpha Cyber Security Internship. I wrote a small Python app with common security mistakes built into it on purpose, then reviewed it, found the problems, and fixed them one at a time.

## What I did
1. Wrote `vulnerable_app.py`, a mock login/notes app with several real-world security mistakes in it.
2. Scanned it with **Bandit**, a free tool that reads Python code and flags risky patterns, without running it.
3. Went through the code by hand too, since a tool doesn't catch everything.
4. Fixed each issue one at a time, and re-ran Bandit after every fix to prove it actually worked.

## Tools I used
- Bandit (automated scanning)
- My own manual review

## How to run the scan yourself
```
python -m venv venv
venv\Scripts\activate
pip install bandit
bandit vulnerable_app.py
```

## Before and after

| | Before | After |
|---|---|---|
| High severity | 3 | 0 |
| Medium severity | 2 | 0 |
| Low severity | 2 | 1 |
| **Total issues** | **7** | **1** |

The one issue left is just Bandit noting that I imported the `subprocess` module at all. That's not a flaw by itself, only a reminder to be careful with it, which I was.

## What I found, and how I fixed it

### 1. Hardcoded credentials (found by reading the code, not by Bandit)
A database password and an API key were written straight into the code:
```python
DB_PASSWORD = "admin123"
API_KEY = "sk_live_51Hc29sXJ9f0q2KzA"
```
Anyone who opens the code, including anyone who finds it on GitHub, sees the real password. Bots actively scan public repos for exactly this. I moved both to environment variables instead, so they live outside the code:
```python
DB_PASSWORD = os.environ.get("DB_PASSWORD", "")
API_KEY = os.environ.get("API_KEY", "")
```
Worth noting: Bandit only flagged the password, not the API key, even though both were equally exposed. That's exactly why the task asks for manual review too.

### 2. SQL injection
The database query was built by gluing text together:
```python
query = "SELECT * FROM users WHERE username = '" + username + "'"
```
A username like `' OR '1'='1` could trick the query into returning data it shouldn't. I switched to a parameterized query, where the value is passed separately instead of pasted into the query text:
```python
query = "SELECT * FROM users WHERE username = ?"
cursor = conn.execute(query, (username,))
```

### 3. Weak password hashing
Passwords were hashed with MD5:
```python
return hashlib.md5(password.encode()).hexdigest()
```
MD5 is fast, which is the opposite of what you want for passwords, since fast means easy to guess at scale. I switched to `scrypt`, which is deliberately slow and uses a random salt so the same password never produces the same stored hash twice:
```python
salt = os.urandom(16)
hashed = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1)
```

### 4. Command injection through ping
A hostname was joined directly into a shell command:
```python
command = "ping -n 1 " + hostname
result = os.popen(command).read()
```
A hostname like `127.0.0.1 & del *.*` would let extra commands ride along. I added a check that only allows letters, numbers, dots and hyphens, and switched to running the command without a shell, using separate arguments instead of one combined string:
```python
if not re.match(r"^[a-zA-Z0-9.\-]+$", hostname):
    return "Invalid hostname"
result = subprocess.run(
    [r"C:\Windows\System32\PING.EXE", "-n", "1", hostname],
    capture_output=True, text=True, shell=False
)
```

### 5. Unsafe use of eval()
User input was handed straight to `eval()`, which runs it as real Python code:
```python
return eval(expression)
```
Someone could type something that imports a module and runs system commands instead of doing math. I replaced it with code that reads the expression's structure and only allows numbers and basic operators, rejecting anything else before it can run.

### 6. Arbitrary command execution
This was the riskiest one. It ran whatever text it was given as an actual shell command, with no checks at all:
```python
def run_saved_command(cmd_string):
    subprocess.call(cmd_string, shell=True)
```
There was no safe way to patch this, so I redesigned it. Now it only accepts a predefined name, which maps to one fixed, pre-written command. Nothing the caller provides is ever run directly:
```python
_ALLOWED_COMMANDS = {
    "check_disk_space": ["wmic", "logicaldisk", "get", "size,freespace,caption"],
    "list_processes": ["tasklist"],
}

def run_saved_command(command_name):
    if command_name not in _ALLOWED_COMMANDS:
        return f"Unknown command: {command_name}"
    result = subprocess.run(
        _ALLOWED_COMMANDS[command_name],
        capture_output=True, text=True, shell=False
    )
    return result.stdout
```

## What I learned
 Bandit caught most of the issues, but it missed the hardcoded API key even though it flagged the password right next to it — that taught me a scanner alone isn’t enough, I still need to read the code myself. Fixing the eval() and shell=True issues also made the risk feel real instead of just a rule I’d heard about, since I could see exactly how a crafted input would break the function.

## Limitations
- This review covers one sample file, not a full application.
- Bandit catches common patterns, but not everything. The hardcoded API key it missed is proof manual review still matters.

## A note on ethics
Scanning and fixing your own code is safe. Never try things like SQL injection or command injection against a system or app you don't own or don't have permission to test.