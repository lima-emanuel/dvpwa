# Security Triage Report

## 1. Grouped Findings

Several tools flagged the same underlying vulnerabilities. These can be grouped as follows:

- **SQL Injection in `sqli/dao/student.py`**:
  - Bandit (B608): Hardcoded SQL expressions (Line 42)
  - Semgrep (`sqlalchemy-execute-raw-query`): Raw query execution (Line 45)
  - Semgrep (`formatted-sql-query`): Formatted SQL query (Line 45)
- **Weak Password Hashing in `sqli/dao/user.py`**:
  - Bandit (B324): Use of weak MD5 hash (Line 41)
  - Semgrep (`md5-used-as-password`): MD5 used as password hash (Line 41)
- **Vulnerable Dependencies (aiohttp)**:
  - pip-audit flagged multiple CVEs (e.g. CVE-2021-21330, CVE-2024-23334, etc.) for `aiohttp` version 3.5.3. All of these map to the same outdated dependency.
- **Third-Party Library Issues in Materialize.js**:
  - Semgrep flagged multiple `unsafe-formatstring` and `detect-non-literal-regexp` issues in `sqli/static/js/materialize.js`.

## 2. False Positives / Low Priority

- **Semgrep: `unsafe-formatstring` and `detect-non-literal-regexp` (`sqli/static/js/materialize.js`)**:
  - *Justification*: These findings exist inside a standard, third-party frontend library (`materialize.js`). Exploring them in the context of our repository reveals they are mostly related to internal layout calculations and logging rather than direct handling of unsanitized user input. Fixing them manually would break the library logic; if needed, the library itself should merely be updated.
- **Semgrep: Docker Compose Warnings (`yaml.docker-compose.security...`)**:
  - *Justification*: Findings about the `redis` container (new privileges, writable filesystem) are good defense-in-depth container hardening steps, but they aren't directly exploitable application codebase flaws.

## 3. Triage Summary Table

| ID  | Tool           | File                      | Severity | Decision     | Justification                                                     |
| --- | -------------- | ------------------------- | -------- | ------------ | ----------------------------------------------------------------- |
| 01  | Bandit/Semgrep | `sqli/dao/student.py`     | High     | Fix          | Unsanitized SQL execution creates a direct SQL Injection risk.    |
| 02  | Bandit/Semgrep | `sqli/dao/user.py`        | High     | Fix          | MD5 is weak and trivial to crack, exposing user passwords.          |
| 03  | pip-audit      | `requirements.txt`        | High     | Mitigate     | Multiple CVEs in outdated `aiohttp`; needs updating.              |
| 04  | Semgrep        | `docker-compose.yml`      | Low      | Hardening    | Container hardening for Redis (no-new-privileges, read_only).     |
| 05  | Semgrep        | `static/js/materialize.js`| Low      | False Pos.   | Third-party library internal variables; not directly exploitable. |

---

## 4. Selected Vulnerabilities for Remediation

### Vulnerability 1: SQL Injection (SQLi)

- **File:** `sqli/dao/student.py`
- **Lines:** 42 - 45
- **Evidence:**

  ```python
  q = ("INSERT INTO students (name) "
       "VALUES ('%(name)s')" % {'name': name})
  await cur.execute(q)
  ```

- **Probable Cause:** The query string is constructed via Python string formatting `%` and directly injects the `name` parameter into the SQL command space, allowing attackers to inject arbitrary SQL logic.
- **Correction Strategy:** Convert the string formatting to parameter binding (e.g., parameterized queries like `VALUES (%s)`) and pass the `name` argument to the `execute` method, shifting the responsibility of sanitization safely to the database driver.

### Vulnerability 2: Weak Password Hashing (Cryptographic Failure)

- **File:** `sqli/dao/user.py`
- **Line:** 41
- **Evidence:**

  ```python
  return self.pwd_hash == md5(password.encode('utf-8')).hexdigest()
  ```

- **Probable Cause:** MD5 is a broken cryptographic hashing algorithm for passwords. It is extremely fast and vulnerable to rainbow table attacks and brute forcing.
- **Correction Strategy:** Replace MD5 with a secure, key-derivation function such as `bcrypt`, `argon2`, or `scrypt` (from the `hashlib` or `werkzeug.security` module). Password generation functions must also be updated, and a migration strategy for existing user passwords should be planned if backward compatibility is required (or force users to reset).
