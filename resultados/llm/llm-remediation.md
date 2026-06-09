# Remediation Plan

## Selected Vulnerability 1

- **Vulnerability**: SQL Injection (SQLi) in `sqli/dao/student.py`
- **Root cause**: The query string in the `create` method is constructed using Python's string formatting (`%`), explicitly injecting the `name` parameter into the SQL statement payload. This allows malicious string input to break out of the `'%(name)s'` quotes and inject arbitrary SQL commands, manipulating the database structure or extracting unauthorized data.
- **Proposed patch**:
  Replace string interpolation with proper database query parameterization mapping (via `aiopg`/`psycopg2`).

  ```python
  # sqli/dao/student.py
  @staticmethod
  async def create(conn: Connection, name: str):
      q = "INSERT INTO students (name) VALUES (%s)"
      async with conn.cursor() as cur:
          await cur.execute(q, (name,))
  ```

- **Regression test**: Write a test that attempts to insert a student with a malicious payload, such as `Robert'); DROP TABLE students;--`. Assert that a student is successfully created with that literal string as their exact name, and that a subsequent `SELECT` confirms the `students` table has not been dropped, proving the application safely parses the input as data.
- **How to confirm on a second vulnerability scan**: Run `bandit` and `semgrep`. The occurrences of `B608` (Bandit) and `sqlalchemy-execute-raw-query` / `formatted-sql-query` (Semgrep) in `sqli/dao/student.py` should disappear, as dynamic query interpolation is no longer present.

## Selected Vulnerability 2

- **Vulnerability**: Weak Password Hashing (Cryptographic Failure) in `sqli/dao/user.py`
- **Root cause**: The application verifies passwords using the MD5 hashing algorithm without a unique salt (`md5(password.encode('utf-8')).hexdigest()`). MD5 is cryptographically broken, susceptible to collision attacks, and its extremely fast computation speed makes it vulnerable to brute-force and rainbow table attacks.
- **Proposed patch**:
  Replace `md5` with a strong, intentionally slow cryptographic hashing function such as `bcrypt`. *Note: this requires adding `bcrypt` to `requirements.txt` and a one-time data migration for existing users.*

  ```python
  # sqli/dao/user.py
  import bcrypt

  def check_password(self, password: str):
      # self.pwd_hash must be stored as a bcrypt format string
      return bcrypt.checkpw(password.encode('utf-8'), self.pwd_hash.encode('utf-8'))
  ```

  *(Alternative context native patch: `hashlib.scrypt` with a cryptographically secure, per-user salt.)*
- **Regression test**: Standard user login functional tests (e.g., `test_login_success`, `test_login_wrong_password`) must still pass when tested against accounts provisioned with new bcrypt hashes. A regression test could also ensure login verification time is meaningfully increased to prove the intentionally slower algorithm is in place to slow brute-forcing.
- **How to confirm on a second vulnerability scan**: Re-run `bandit` and `semgrep`. The occurrences of `B324` (Bandit) and `md5-used-as-password` (Semgrep) in `sqli/dao/user.py` should be dismissed, showing MD5 is no longer in the execution path.
