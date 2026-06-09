# Security Triage Prompt

## System Instructions

You are an expert security engineer reviewing the results of automated security scans.
Your task is to analyze the findings below, prioritize them by severity, and provide
actionable remediation steps. Focus on findings that pose the greatest risk to the
application's security posture.

For each finding:
1. Verify the vulnerability exists by examining the code snippet provided
2. Assess the actual risk considering exploitability and context
3. Provide specific remediation guidance
4. Flag any findings that are false positives (with justification)

---

## Executive Summary

| Tool | Findings |
|------|----------|
| Bandit | 2 |
| Semgrep | 9 |
| pip-audit | 52 |
| gitleaks | 0 |
| **Total** | **63** |

**Critical/High Severity:** 24
**Medium Severity:** 31
**Low/Info Severity:** 3

---

## Bandit Findings

Bandit is a Python-focused static analysis tool that detects common security issues.

### 🔴 HIGH - sqli/dao/user.py:41

**Test ID:** `B324`

**Description:** Use of weak MD5 hash for security. Consider usedforsecurity=False

**Code Snippet (python):**
```python
      38 |             return User.from_raw(await cur.fetchone())
      39 | 
      40 |     def check_password(self, password: str):
>>>   41 |         return self.pwd_hash == md5(password.encode('utf-8')).hexdigest()
```

**More Info:** https://bandit.readthedocs.io/en/1.9.4/plugins/b324_hashlib.html


### 🟡 MEDIUM - sqli/dao/student.py:42

**Test ID:** `B608`

**Description:** Possible SQL injection vector through string-based query construction.

**Code Snippet (python):**
```python
      39 | 
      40 |     @staticmethod
      41 |     async def create(conn: Connection, name: str):
>>>   42 |         q = ("INSERT INTO students (name) "
      43 |              "VALUES ('%(name)s')" % {'name': name})
      44 |         async with conn.cursor() as cur:
      45 |             await cur.execute(q)
```

**More Info:** https://bandit.readthedocs.io/en/1.9.4/plugins/b608_hardcoded_sql_expressions.html


---

## Semgrep Findings

Semgrep is a fast, open-source static analysis tool that finds vulnerabilities via pattern matching.

### 🔴 HIGH - sqli/dao/student.py:45

**Rule ID:** `python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query`

**Description:** Avoiding SQL string concatenation: untrusted input concatenated with raw SQL query can result in SQL Injection. In order to execute raw query safely, prepared statement should be used. SQLAlchemy provides TextualSQL to easily used prepared statement with named parameters. For complex SQL composition, use SQL Expression Language or Schema Definition Language. In most cases, SQLAlchemy ORM will be a better option.

**Code Snippet (python):**
```python
      42 |         q = ("INSERT INTO students (name) "
      43 |              "VALUES ('%(name)s')" % {'name': name})
      44 |         async with conn.cursor() as cur:
>>>   45 |             await cur.execute(q)
      46 | 
      47 | 
```

### WARNING - docker-compose.yml:11

**Rule ID:** `yaml.docker-compose.security.no-new-privileges.no-new-privileges`

**Description:** Service 'redis' allows for privilege escalation via setuid or setgid binaries. Add 'no-new-privileges:true' in 'security_opt' to prevent this.

**Code Snippet (yaml):**
```yaml
       8 |     ports:
       9 |       - 5432:5432
      10 | 
>>>   11 |   redis:
      12 |     image: redis:alpine
      13 | 
      14 |   sqli:
```

### WARNING - docker-compose.yml:11

**Rule ID:** `yaml.docker-compose.security.writable-filesystem-service.writable-filesystem-service`

**Description:** Service 'redis' is running with a writable root filesystem. This may allow malicious applications to download and run additional payloads, or modify container files. If an application inside a container has to save something temporarily consider using a tmpfs. Add 'read_only: true' to this service to prevent this.

**Code Snippet (yaml):**
```yaml
       8 |     ports:
       9 |       - 5432:5432
      10 | 
>>>   11 |   redis:
      12 |     image: redis:alpine
      13 | 
      14 |   sqli:
```

### WARNING - sqli/dao/student.py:45

**Rule ID:** `python.lang.security.audit.formatted-sql-query.formatted-sql-query`

**Description:** Detected possible formatted SQL query. Use parameterized queries instead.

**Code Snippet (python):**
```python
      42 |         q = ("INSERT INTO students (name) "
      43 |              "VALUES ('%(name)s')" % {'name': name})
      44 |         async with conn.cursor() as cur:
>>>   45 |             await cur.execute(q)
      46 | 
      47 | 
```

### WARNING - sqli/dao/user.py:41

**Rule ID:** `python.lang.security.audit.md5-used-as-password.md5-used-as-password`

**Description:** It looks like MD5 is used as a password hash. MD5 is not considered a secure password hash because it can be cracked by an attacker in a short amount of time. Use a suitable password hashing function such as scrypt. You can use `hashlib.scrypt`.

**Code Snippet (python):**
```python
      38 |             return User.from_raw(await cur.fetchone())
      39 | 
      40 |     def check_password(self, password: str):
>>>   41 |         return self.pwd_hash == md5(password.encode('utf-8')).hexdigest()
```

### WARNING - sqli/static/js/materialize.js:565

**Rule ID:** `javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp`

**Description:** RegExp() called with a `t` function argument, this might allow an attacker to cause a Regular Expression Denial-of-Service (ReDoS) within your application as RegExP blocks the main thread. For this reason, it is recommended to use hardcoded regexes instead. If your regex is run on user-controlled input, consider performing input validation or use a regex checking/sanitization library such as https://www.npmjs.com/package/recheck to verify that the regex does not appear vulnerable to ReDoS.

**Code Snippet (javascript):**
```javascript
     562 |         }, addClass: function (e, t) {
     563 |           e.classList ? e.classList.add(t) : e.className += (e.className.length ? " " : "") + t;
     564 |         }, removeClass: function (e, t) {
>>>  565 |           e.classList ? e.classList.remove(t) : e.className = e.className.toString().replace(new RegExp("(^|\\s)" + t.split(" ").join("|") + "(\\s|$)", "gi"), " ");
     566 |         } }, getPropertyValue: function (e, r, n, o) {
     567 |         function s(e, r) {
     568 |           function n() {
```

### 🟢 LOW - sqli/static/js/materialize.js:645

**Rule ID:** `javascript.lang.security.audit.unsafe-formatstring.unsafe-formatstring`

**Description:** Detected string concatenation with a non-literal variable in a util.format / console.log function. If an attacker injects a format specifier in the string, it will forge the log message. Try to use constant values for the format string.

**Code Snippet (javascript):**
```javascript
     642 |               }), b.CSS.setPropertyValue(u, "position", e.position), b.CSS.setPropertyValue(u, "fontSize", e.fontSize), b.CSS.setPropertyValue(u, "boxSizing", "content-box"), f.each(["minWidth", "maxWidth", "width", "minHeight", "maxHeight", "height"], function (e, t) {
     643 |                 b.CSS.setPropertyValue(u, t, s + "%");
     644 |               }), b.CSS.setPropertyValue(u, "paddingLeft", s + "em"), l.percentToPxWidth = L.lastPercentToPxWidth = (parseFloat(S.getPropertyValue(u, "width", null, !0)) || 1) / s, l.percentToPxHeight = L.lastPercentToPxHeight = (parseFloat(S.getPropertyValue(u, "height", null, !0)) || 1) / s, l.emToPx = L.lastEmToPx = (parseFloat(S.getPropertyValue(u, "paddingLeft")) || 1) / s, e.myParent.removeChild(u);
>>>  645 |             }return null === L.remToPx && (L.remToPx = parseFloat(S.getPropertyValue(r.body, "fontSize")) || 16), null === L.vwToPx && (L.vwToPx = parseFloat(t.innerWidth) / 100, L.vhToPx = parseFloat(t.innerHeight) / 100), l.remToPx = L.remToPx, l.vwToPx = L.vwToPx, l.vhToPx = L.vhToPx, b.debug >= 1 && console.log("Unit ratios: " + JSON.stringify(l), o), l;
     646 |           }if (s.begin && 0 === V) try {
     647 |             s.begin.call(g, g);
     648 |           } catch (x) {
```

### 🟢 LOW - sqli/static/js/materialize.js:661

**Rule ID:** `javascript.lang.security.audit.unsafe-formatstring.unsafe-formatstring`

**Description:** Detected string concatenation with a non-literal variable in a util.format / console.log function. If an attacker injects a format specifier in the string, it will forge the log message. Try to use constant values for the format string.

**Code Snippet (javascript):**
```javascript
     658 |           } else if ("reverse" === A) {
     659 |             if (!i(o).tweensContainer) return void f.dequeue(o, s.queue);"none" === i(o).opts.display && (i(o).opts.display = "auto"), "hidden" === i(o).opts.visibility && (i(o).opts.visibility = "visible"), i(o).opts.loop = !1, i(o).opts.begin = null, i(o).opts.complete = null, v.easing || delete s.easing, v.duration || delete s.duration, s = f.extend({}, i(o).opts, s);var E = f.extend(!0, {}, i(o).tweensContainer);for (var H in E) {
     660 |               if ("element" !== H) {
>>>  661 |                 var N = E[H].startValue;E[H].startValue = E[H].currentValue = E[H].endValue, E[H].endValue = N, m.isEmptyObject(v) || (E[H].easing = s.easing), b.debug && console.log("reverse tweensContainer (" + H + "): " + JSON.stringify(E[H]), o);
     662 |               }
     663 |             }l = E;
     664 |           } else if ("start" === A) {
```

### 🟢 LOW - sqli/static/js/materialize.js:699

**Rule ID:** `javascript.lang.security.audit.unsafe-formatstring.unsafe-formatstring`

**Description:** Detected string concatenation with a non-literal variable in a util.format / console.log function. If an attacker injects a format specifier in the string, it will forge the log message. Try to use constant values for the format string.

**Code Snippet (javascript):**
```javascript
     696 |                     q = M + q;break;case "-":
     697 |                     q = M - q;break;case "*":
     698 |                     q = M * q;break;case "/":
>>>  699 |                     q = M / q;}l[z] = { rootPropertyValue: B, startValue: M, currentValue: M, endValue: q, unitType: G, easing: $ }, b.debug && console.log("tweensContainer (" + z + "): " + JSON.stringify(l[z]), o);
     700 |               } else b.debug && console.log("Skipping [" + I + "] due to a lack of browser support.");
     701 |             }l.element = o;
     702 |           }l.element && (S.Values.addClass(o, "velocity-animating"), R.push(l), "" === s.queue && (i(o).tweensContainer = l, i(o).opts = s), i(o).isAnimating = !0, V === w - 1 ? (b.State.calls.push([R, g, s, null, k.resolver]), b.State.isTicking === !1 && (b.State.isTicking = !0, c())) : V++);
```

---

## pip-audit Findings

pip-audit checks Python dependencies for known vulnerabilities.

### 🔴 HIGH - aiohttp (3.5.3)

**Vulnerability ID:** `PYSEC-2021-76`

**CVE IDs:** CVE-2021-21330

**Fixed Versions:** 3.7.4

**Description:** aiohttp is an asynchronous HTTP client/server framework for asyncio and Python. In aiohttp before version 3.7.4 there is an open redirect vulnerability. A maliciously crafted link to an aiohttp-based web-server could redirect the browser to a different website. It is caused by a bug in the `aiohttp.web_middlewares.normalize_path_middleware` middleware. This security problem has been fixed in 3.7.4. Upgrade your dependency using pip as follows "pip install aiohttp >= 3.7.4". If upgrading is not a...

### 🔴 HIGH - aiohttp (3.5.3)

**Vulnerability ID:** `PYSEC-2021-76`

**CVE IDs:** CVE-2021-21330

**Fixed Versions:** 3.7.4

**Description:** ### Impact  Open redirect vulnerability — a maliciously crafted link to an aiohttp-based web-server could redirect the browser to a different website.  It is caused by a bug in the `aiohttp.web_middlewares.normalize_path_middleware` middleware.  ### Patches  This security problem has been fixed in v3.7.4. Upgrade your dependency as follows: [`pip install aiohttp >= 3.7.4`]  ### Workarounds  If upgrading is not an option for you, a workaround can be to avoid using `aiohttp.web_middlewares.normali...

### 🔴 HIGH - aiohttp (3.5.3)

**Vulnerability ID:** `PYSEC-2024-24`

**CVE IDs:** CVE-2024-23334

**Fixed Versions:** 3.9.2

**Description:** aiohttp is an asynchronous HTTP client/server framework for asyncio and Python. When using aiohttp as a web server and configuring static routes, it is necessary to specify the root path for static files. Additionally, the option 'follow_symlinks' can be used to determine whether to follow symbolic links outside the static root directory. When 'follow_symlinks' is set to True, there is no validation to check if reading a file is within the root directory. This can lead to directory traversal vul...

### 🔴 HIGH - aiohttp (3.5.3)

**Vulnerability ID:** `PYSEC-2023-120`

**CVE IDs:** CVE-2023-37276

**Fixed Versions:** 3.8.5

**Description:** ### Impact  aiohttp v3.8.4 and earlier are [bundled with llhttp v6.0.6](https://github.com/aio-libs/aiohttp/blob/v3.8.4/.gitmodules) which is vulnerable to CVE-2023-30589. The vulnerable code is used by aiohttp for its HTTP request parser when available which is the default case when installing from a wheel.  This vulnerability only affects users of aiohttp as an HTTP server (ie `aiohttp.Application`), you are not affected by this vulnerability if you are using aiohttp as an HTTP client library ...

### 🔴 HIGH - aiohttp (3.5.3)

**Vulnerability ID:** `PYSEC-2023-250`

**CVE IDs:** CVE-2023-49081

**Fixed Versions:** 3.9.0

**Description:** aiohttp is an asynchronous HTTP client/server framework for asyncio and Python. Improper validation made it possible for an attacker to modify the HTTP request (e.g. to insert a new header) or create a new HTTP request if the attacker controls the HTTP version. The vulnerability only occurs if the attacker can control the HTTP version of the request. This issue has been patched in version 3.9.0.

### 🔴 HIGH - aiohttp (3.5.3)

**Vulnerability ID:** `PYSEC-2023-251`

**CVE IDs:** CVE-2023-49082

**Fixed Versions:** 3.9.0

**Description:** aiohttp is an asynchronous HTTP client/server framework for asyncio and Python. Improper validation makes it possible for an attacker to modify the HTTP request (e.g. insert a new header) or even create a new HTTP request if the attacker controls the HTTP method. The vulnerability occurs only if the attacker can control the HTTP method (GET, POST etc.) of the request. If the attacker can control the HTTP version of the request it will be able to modify the request (request smuggling). This issue...

### 🔴 HIGH - aiohttp (3.5.3)

**Vulnerability ID:** `PYSEC-2024-24`

**CVE IDs:** CVE-2024-23334

**Fixed Versions:** 3.9.2

**Description:** ### Summary Improperly configuring static resource resolution in aiohttp when used as a web server can result in the unauthorized reading of arbitrary files on the system.  ### Details When using aiohttp as a web server and configuring static routes, it is necessary to specify the root path for static files. Additionally, the option 'follow_symlinks' can be used to determine whether to follow symbolic links outside the static root directory. When 'follow_symlinks' is set to True, there is no val...

### 🔴 HIGH - aiohttp (3.5.3)

**Vulnerability ID:** `PYSEC-2024-26`

**CVE IDs:** CVE-2024-23829

**Fixed Versions:** 3.9.2

**Description:** ### Summary Security-sensitive parts of the *Python HTTP parser* retained minor differences in allowable character sets, that must trigger error handling to robustly match frame boundaries of proxies in order to protect against injection of additional requests. Additionally, validation could trigger exceptions that were not handled consistently with processing of other malformed input.  ### Details These problems are rooted in pattern matching protocol elements, previously improved by PR #3235 a...

### 🔴 HIGH - aiohttp (3.5.3)

**Vulnerability ID:** `PYSEC-2023-246`

**CVE IDs:** CVE-2023-47627

**Fixed Versions:** 3.8.6

**Description:** # Summary The HTTP parser in AIOHTTP has numerous problems with header parsing, which could lead to request smuggling. This parser is only used when `AIOHTTP_NO_EXTENSIONS` is enabled (or not using a prebuilt wheel).   # Details  ## Bug 1: Bad parsing of `Content-Length` values  ### Description RFC 9110 says this: > `Content-Length = 1*DIGIT`  AIOHTTP does not enforce this rule, presumably because of an incorrect usage of the builtin `int` constructor. Because the `int` constructor accepts `+` a...

### 🔴 HIGH - aiohttp (3.5.3)

**Vulnerability ID:** `PYSEC-2023-246`

**CVE IDs:** CVE-2023-47627

**Fixed Versions:** 3.8.6

**Description:** aiohttp is an asynchronous HTTP client/server framework for asyncio and Python. The HTTP parser in AIOHTTP has numerous problems with header parsing, which could lead to request smuggling. This parser is only used when AIOHTTP_NO_EXTENSIONS is enabled (or not using a prebuilt wheel). These bugs have been addressed in commit `d5c12ba89` which has been included in release version 3.8.6. Users are advised to upgrade. There are no known workarounds for these issues.

### 🔴 HIGH - aiohttp (3.5.3)

**Vulnerability ID:** `PYSEC-2023-247`

**CVE IDs:** CVE-2023-47641

**Fixed Versions:** 3.8.0

**Description:** aiohttp is an asynchronous HTTP client/server framework for asyncio and Python. Affected versions of aiohttp have a security vulnerability regarding the inconsistent interpretation of the http protocol. HTTP/1.1 is a persistent protocol, if both Content-Length(CL) and Transfer-Encoding(TE) header values are present it can lead to incorrect interpretation of two entities that parse the HTTP and we can poison other sockets with this incorrect interpretation. A possible Proof-of-Concept (POC) would...

### 🔴 HIGH - aiohttp (3.5.3)

**Vulnerability ID:** `PYSEC-2023-251`

**CVE IDs:** CVE-2023-49082

**Fixed Versions:** 3.9.0

**Description:** ### Summary Improper validation makes it possible for an attacker to modify the HTTP request (e.g. insert a new header) or even create a new HTTP request if the attacker controls the HTTP method.  ### Details The vulnerability occurs only if the attacker can control the HTTP method (GET, POST etc.) of the request.  Previous releases performed no validation on the provided value. If an attacker controls the HTTP method it will be used as is and can lead to HTTP request smuggling.  ### PoC A minim...

### 🔴 HIGH - aiohttp (3.5.3)

**Vulnerability ID:** `PYSEC-2023-250`

**CVE IDs:** CVE-2023-49081

**Fixed Versions:** 3.9.0

**Description:** ### Summary Improper validation make it possible for an attacker to modify the HTTP request (e.g. to insert a new header) or even create a new HTTP request if the attacker controls the HTTP version.  ### Details The vulnerability only occurs if the attacker can control the HTTP version of the request (including its type). For example if an unvalidated JSON value is used as a version and the attacker is then able to pass an array as the `version` parameter. Furthermore, the vulnerability only occ...

### 🔴 HIGH - aiohttp (3.5.3)

**Vulnerability ID:** `PYSEC-2024-26`

**CVE IDs:** CVE-2024-23829

**Fixed Versions:** 3.9.2

**Description:** aiohttp is an asynchronous HTTP client/server framework for asyncio and Python. Security-sensitive parts of the Python HTTP parser retained minor differences in allowable character sets, that must trigger error handling to robustly match frame boundaries of proxies in order to protect against injection of additional requests. Additionally, validation could trigger exceptions that were not handled consistently with processing of other malformed input.  Being more lenient than internet standards r...

### 🔴 HIGH - idna (2.8)

**Vulnerability ID:** `PYSEC-2024-60`

**CVE IDs:** CVE-2024-3651

**Fixed Versions:** 3.7

**Description:** ### Impact A specially crafted argument to the `idna.encode()` function could consume significant resources. This may lead to a denial-of-service.  ### Patches The function has been refined to reject such strings without the associated resource consumption in version 3.7.  ### Workarounds Domain names cannot exceed 253 characters in length, if this length limit is enforced prior to passing the domain to the `idna.encode()` function it should no longer consume significant resources. This is trigg...

### 🔴 HIGH - idna (2.8)

**Vulnerability ID:** `PYSEC-2024-60`

**CVE IDs:** CVE-2024-3651

**Fixed Versions:** 3.7

**Description:** A vulnerability was identified in the kjd/idna library, specifically within the `idna.encode()` function, affecting version 3.6. The issue arises from the function's handling of crafted input strings, which can lead to quadratic complexity and consequently, a denial of service condition. This vulnerability is triggered by a crafted input that causes the `idna.encode()` function to process the input with considerable computational load, significantly increasing the processing time in a quadratic ...

### 🔴 HIGH - jinja2 (2.10)

**Vulnerability ID:** `PYSEC-2021-66`

**CVE IDs:** CVE-2020-28493

**Fixed Versions:** 2.11.3

**Description:** This affects the package jinja2 from 0.0.0 and before 2.11.3. The ReDoS vulnerability is mainly due to the `_punctuation_re regex` operator and its use of multiple wildcards. The last wildcard is the most exploitable as it searches for trailing punctuation. This issue can be mitigated by Markdown to format user content instead of the urlize filter, or by implementing request timeouts and limiting process memory.

### 🔴 HIGH - jinja2 (2.10)

**Vulnerability ID:** `PYSEC-2019-217`

**CVE IDs:** CVE-2019-10906

**Fixed Versions:** 2.10.1

**Description:** In Pallets Jinja before 2.10.1, str.format_map allows a sandbox escape.

### 🔴 HIGH - pyjwt (2.12.1)

**Vulnerability ID:** `PYSEC-2026-179`

**CVE IDs:** CVE-2026-48526

**Fixed Versions:** 2.13.0

**Description:** PyJWT is a JSON Web Token implementation in Python. Prior to 2.13.0, when the verifier is decoding JSON Web Tokens, while supporting both asymmetric and HMAC algorithms, the library does not validate use of JSON Web Keys in HMAC algorithm, allowing attacker to use the issuer public key as the secret key for HMAC algorithm. This vulnerability is fixed in 2.13.0.

### 🔴 HIGH - pyjwt (2.12.1)

**Vulnerability ID:** `PYSEC-2026-175`

**CVE IDs:** CVE-2026-48522

**Fixed Versions:** 2.13.0

**Description:** PyJWT is a JSON Web Token implementation in Python. Prior to 2.13.0, PyJWKClient passes its uri argument directly to urllib.request.urlopen() which uses Python stdlib's default OpenerDirector registering HTTPHandler, HTTPSHandler, FTPHandler, FileHandler, and DataHandler. There is currently no documented option to restrict which schemes PyJWKClient will fetch. If an application's jku URL ingestion path accepts attacker-influenced URLs (e.g., from JWT header, configuration file, OAuth flow parame...

### 🔴 HIGH - pyjwt (2.12.1)

**Vulnerability ID:** `PYSEC-2026-177`

**CVE IDs:** CVE-2026-48524

**Fixed Versions:** 2.13.0

**Description:** PyJWT is a JSON Web Token implementation in Python. Prior to 2.13.0, PyJWKClient.get_signing_key() forces a fresh HTTP request to the JWKS endpoint for every JWT with an unknown kid value, with no rate limiting. Since kid comes from the unverified token header, an attacker can trigger unlimited outbound requests. The vulnerability surfaces only when a JWKS fetch fails; an attacker can attempt to provoke that with sustained unknown-kid traffic, but the outcome depends on upstream JWKS-endpoint be...

### 🔴 HIGH - pyjwt (2.12.1)

**Vulnerability ID:** `PYSEC-2026-178`

**CVE IDs:** CVE-2026-48525

**Fixed Versions:** 2.13.0

**Description:** PyJWT is a JSON Web Token implementation in Python. From 2.8.0 to 2.12.1, when verifying detached JWS tokens using the unencoded-payload option ("b64": false, RFC 7797), PyJWT performs Base64URL decoding of the compact-serialization payload segment before enforcing the detached-payload rules. For b64=false, PyJWT later discards that decoded payload and replaces it with the caller-provided detached_payload. In practice, this turns the middle segment into an attacker-controlled “work amplifier”: a...

### 🟡 MEDIUM - aiohttp (3.5.3)

**Vulnerability ID:** `CVE-2026-34515`

**Fixed Versions:** 3.13.4

**Description:** ### Summary  On Windows the static resource handler may expose information about a NTLMv2 remote path.  ### Impact  If an application is running on Windows, and using aiohttp's static resource handler (not recommended in production), then it may be possible for an attacker to extract the hash from an NTLMv2 path and then extract the user's credentials from there.  -----  Patch: https://github.com/aio-libs/aiohttp/commit/0ae2aa076c84573df83fc1fdc39eec0f5862fe3d

### 🟡 MEDIUM - aiohttp (3.5.3)

**Vulnerability ID:** `CVE-2026-34513`

**Fixed Versions:** 3.13.4

**Description:** ### Summary  An unbounded DNS cache could result in excessive memory usage possibly resulting in a DoS situation.  ### Impact  If an application makes requests to a very large number of hosts, this could cause the DNS cache to continue growing and slowly use excessive amounts of memory.  -----  Patch: https://github.com/aio-libs/aiohttp/commit/c4d77c3533122be353b8afca8e8675e3b4cbda98

### 🟡 MEDIUM - aiohttp (3.5.3)

**Vulnerability ID:** `CVE-2026-34516`

**Fixed Versions:** 3.13.4

**Description:** ### Summary  A response with an excessive number of multipart headers may be allowed to use more memory than intended, potentially allowing a DoS vulnerability.  ### Impact  Multipart headers were not subject to the same size restrictions in place for normal headers, potentially allowing substantially more data to be loaded into memory than intended. However, other restrictions in place limit the impact of this vulnerability.  -----  Patch: https://github.com/aio-libs/aiohttp/commit/8a74257b3804...

### 🟡 MEDIUM - aiohttp (3.5.3)

**Vulnerability ID:** `GHSA-pjjw-qhg8-p2p9`

**Fixed Versions:** 3.8.6

**Description:** ### Summary llhttp 8.1.1 is vulnerable to two request smuggling vulnerabilities. Details have not been disclosed yet, so refer to llhttp for future information. The issue is resolved by using llhttp 9+ (which is included in aiohttp 3.8.6+).

### 🟡 MEDIUM - aiohttp (3.5.3)

**Vulnerability ID:** `CVE-2026-34517`

**Fixed Versions:** 3.13.4

**Description:** ### Summary  For some multipart form fields, aiohttp read the entire field into memory before checking client_max_size.  ### Impact  If an application uses `Request.post()` an attacker can send a specially crafted multipart request to force significant temporary memory allocation even when the request is ultimately rejected.  -----  Patch: https://github.com/aio-libs/aiohttp/commit/cbb774f38330563422ca0c413a71021d7b944145

### 🟡 MEDIUM - aiohttp (3.5.3)

**Vulnerability ID:** `CVE-2026-34519`

**Fixed Versions:** 3.13.4

**Description:** ### Summary  An attacker who controls the `reason` parameter when creating a `Response` may be able to inject extra headers or similar exploits.  ### Impact  In the unlikely situation that an application allows untrusted data to be used in the response's `reason` parameter, then an attacker could manipulate the response to send something different from what the developer intended.  -----  Patch: https://github.com/aio-libs/aiohttp/commit/53b35a2f8869c37a133e60bf1a82a1c01642ba2b

### 🟡 MEDIUM - aiohttp (3.5.3)

**Vulnerability ID:** `CVE-2026-34518`

**Fixed Versions:** 3.13.4

**Description:** ### Summary  When following redirects to a different origin, aiohttp drops the Authorization header, but retains the Cookie and Proxy-Authorization headers.  ### Impact  The Cookie and Proxy-Authorizations headers could contain sensitive information which may be leaked to an unintended party after following a redirect.  -----  Patch: https://github.com/aio-libs/aiohttp/commit/5351c980dcec7ad385730efdf4e1f4338b24fdb6

### 🟡 MEDIUM - aiohttp (3.5.3)

**Vulnerability ID:** `CVE-2026-34520`

**Fixed Versions:** 3.13.4

**Description:** ### Summary  The C parser (the default for most installs) accepted null bytes and control characters is response headers.  ### Impact  An attacker could send header values that are interpreted differently than expected due to the presence of control characters. For example, `request.url.origin()` may return a different value than the raw Host header, or what a reverse proxy interpreted it as., potentially resulting in some kind of security bypass.  -----  Patch: https://github.com/aio-libs/aioht...

### 🟡 MEDIUM - aiohttp (3.5.3)

**Vulnerability ID:** `CVE-2024-27306`

**Fixed Versions:** 3.9.4

**Description:** ### Summary  A XSS vulnerability exists on index pages for static file handling.  ### Details  When using `web.static(..., show_index=True)`, the resulting index pages do not escape file names.  If users can upload files with arbitrary filenames to the static directory, the server is vulnerable to XSS attacks.  ### Workaround  We have always recommended using a reverse proxy server (e.g. nginx) for serving static files. Users following the recommendation are unaffected.  Other users can disable ...

### 🟡 MEDIUM - aiohttp (3.5.3)

**Vulnerability ID:** `CVE-2024-30251`

**Fixed Versions:** 3.9.4

**Description:** ### Summary An attacker can send a specially crafted POST (multipart/form-data) request. When the aiohttp server processes it, the server will enter an infinite loop and be unable to process any further requests.  ### Impact An attacker can stop the application from serving requests after sending a single request.  -------  For anyone needing to patch older versions of aiohttp, the minimum diff needed to resolve the issue is (located in `_read_chunk_from_length()`):  ```diff diff --git a/aiohttp...

### 🟡 MEDIUM - aiohttp (3.5.3)

**Vulnerability ID:** `CVE-2026-34525`

**Fixed Versions:** 3.13.4

**Description:** ### Summary  Multiple Host headers were allowed in aiohttp.  ### Impact  Mostly this doesn't affect aiohttp security itself, but if a reverse proxy is applying security rules depending on the target Host, it is theoretically possible that the proxy and aiohttp could process different host names, possibly resulting in bypassing a security check on the proxy and getting a request processed by aiohttp in a privileged sub app when using `Application.add_domain()`.  -----  Patch: https://github.com/a...

### 🟡 MEDIUM - aiohttp (3.5.3)

**Vulnerability ID:** `CVE-2024-52304`

**Fixed Versions:** 3.10.11

**Description:** ### Summary The Python parser parses newlines in chunk extensions incorrectly which can lead to request smuggling vulnerabilities under certain conditions.  ### Impact If a pure Python version of aiohttp is installed (i.e. without the usual C extensions) or `AIOHTTP_NO_EXTENSIONS` is enabled, then an attacker may be able to execute a request smuggling attack to bypass certain firewalls or proxy protections.  -----  Patch: https://github.com/aio-libs/aiohttp/commit/259edc369075de63e6f3a4eaade058c...

### 🟡 MEDIUM - aiohttp (3.5.3)

**Vulnerability ID:** `CVE-2025-53643`

**Fixed Versions:** 3.12.14

**Description:** ### Summary The Python parser is vulnerable to a request smuggling vulnerability due to not parsing trailer sections of an HTTP request.  ### Impact If a pure Python version of aiohttp is installed (i.e. without the usual C extensions) or AIOHTTP_NO_EXTENSIONS is enabled, then an attacker may be able to execute a request smuggling attack to bypass certain firewalls or proxy protections.  ----  Patch: https://github.com/aio-libs/aiohttp/commit/e8d774f635dc6d1cd3174d0e38891da5de0e2b6a

### 🟡 MEDIUM - aiohttp (3.5.3)

**Vulnerability ID:** `CVE-2025-69223`

**Fixed Versions:** 3.13.3

**Description:** ### Summary A zip bomb can be used to execute a DoS against the aiohttp server.  ### Impact An attacker may be able to send a compressed request that when decompressed by aiohttp could exhaust the host's memory.  ------  Patch: https://github.com/aio-libs/aiohttp/commit/2b920c39002cee0ec5b402581779bbaaf7c9138a

### 🟡 MEDIUM - aiohttp (3.5.3)

**Vulnerability ID:** `CVE-2025-69224`

**Fixed Versions:** 3.13.3

**Description:** ### Summary The Python HTTP parser may allow a request smuggling attack with the presence of non-ASCII characters.  ### Impact If a pure Python version of aiohttp is installed (i.e. without the usual C extensions) or AIOHTTP_NO_EXTENSIONS is enabled, then an attacker may be able to execute a request smuggling attack to bypass certain firewalls or proxy protections.  ------  Patch: https://github.com/aio-libs/aiohttp/commit/32677f2adfd907420c078dda6b79225c6f4ebce0

### 🟡 MEDIUM - aiohttp (3.5.3)

**Vulnerability ID:** `CVE-2025-69228`

**Fixed Versions:** 3.13.3

**Description:** ### Summary A request can be crafted in such a way that an aiohttp server's memory fills up uncontrollably during processing.  ### Impact If an application includes a handler that uses the `Request.post()` method, an attacker may be able to freeze the server by exhausting the memory.  -----  Patch: https://github.com/aio-libs/aiohttp/commit/b7dbd35375aedbcd712cbae8ad513d56d11cce60

### 🟡 MEDIUM - aiohttp (3.5.3)

**Vulnerability ID:** `CVE-2025-69229`

**Fixed Versions:** 3.13.3

**Description:** ### Summary  Handling of chunked messages can result in excessive blocking CPU usage when receiving a large number of chunks.  ### Impact  If an application makes use of the `request.read()` method in an endpoint, it may be possible for an attacker to cause the server to spend a moderate amount of blocking CPU time (e.g. 1 second) while processing the request. This could potentially lead to DoS as the server would be unable to handle other requests during that time.  -----  Patch: https://github...

### 🟡 MEDIUM - aiohttp (3.5.3)

**Vulnerability ID:** `CVE-2025-69230`

**Fixed Versions:** 3.13.3

**Description:** ### Summary Reading multiple invalid cookies can lead to a logging storm.  ### Impact If the ``cookies`` attribute is accessed in an application, then an attacker may be able to trigger a storm of warning-level logs using a specially crafted Cookie header.  ----  Patch: https://github.com/aio-libs/aiohttp/commit/64629a0834f94e46d9881f4e99c41a137e1f3326

### 🟡 MEDIUM - aiohttp (3.5.3)

**Vulnerability ID:** `CVE-2025-69226`

**Fixed Versions:** 3.13.3

**Description:** ### Summary Path normalization for static files prevents path traversal, but opens up the ability for an attacker to ascertain the existence of absolute path components.  ### Impact If an application uses `web.static()` (not recommended for production deployments), it may be possible for an attacker to ascertain the existence of path components.  ------  Patch: https://github.com/aio-libs/aiohttp/commit/f2a86fd5ac0383000d1715afddfa704413f0711e

### 🟡 MEDIUM - aiohttp (3.5.3)

**Vulnerability ID:** `CVE-2025-69227`

**Fixed Versions:** 3.13.3

**Description:** ### Summary When assert statements are bypassed, an infinite loop can occur, resulting in a DoS attack when processing a POST body.  ### Impact If optimisations are enabled (`-O` or `PYTHONOPTIMIZE=1`), and the application includes a handler that uses the `Request.post()` method, then an attacker may be able to execute a DoS attack with a specially crafted message.  ------  Patch: https://github.com/aio-libs/aiohttp/commit/bc1319ec3cbff9438a758951a30907b072561259

### 🟡 MEDIUM - aiohttp (3.5.3)

**Vulnerability ID:** `CVE-2025-69225`

**Fixed Versions:** 3.13.3

**Description:** ### Summary  The parser allows non-ASCII decimals to be present in the Range header.  ### Impact  There is no known impact, but there is the possibility that there's a method to exploit a request smuggling vulnerability.  ----  Patch: https://github.com/aio-libs/aiohttp/commit/c7b7a044f88c71cefda95ec75cdcfaa4792b3b96

### 🟡 MEDIUM - aiohttp (3.5.3)

**Vulnerability ID:** `CVE-2026-22815`

**Fixed Versions:** 3.13.4

**Description:** ### Summary  Insufficient restrictions in header/trailer handling could cause uncapped memory usage.  ### Impact  An application could cause memory exhaustion when receiving an attacker controlled request or response. A vulnerable web application could mitigate these risks with a typical reverse proxy configuration.  -----  Patch: https://github.com/aio-libs/aiohttp/commit/0c2e9da51126238a421568eb7c5b53e5b5d17b36

### 🟡 MEDIUM - aiohttp (3.5.3)

**Vulnerability ID:** `CVE-2026-34514`

**Fixed Versions:** 3.13.4

**Description:** ### Summary  An attacker who controls the `content_type` parameter in aiohttp could use this to inject extra headers or similar exploits.  ### Impact  If an application allows untrusted data to be used for the multipart `content_type` parameter when constructing a request, an attacker may be able to manipulate the request to send something other than what the developer intended.  -----  Patch: https://github.com/aio-libs/aiohttp/commit/9a6ada97e2c6cf1ce31727c6c9fcea17c21f6f06

### 🟡 MEDIUM - aiohttp (3.5.3)

**Vulnerability ID:** `CVE-2026-34993`

**Fixed Versions:** 3.14.0

**Description:** ### Summary  Using ``CookieJar.load()`` with untrusted input may allow arbitrary code execution.  ### Impact  Most applications using this function will be doing so with the user's own data, so this is unlikely to affect many applications.  ### Workaround  If an application does allow attacker controlled files to be loaded, a workaround on older releases would be to sanitise the files before loading.  -----  Patch: https://github.com/aio-libs/aiohttp/commit/dcf40f30637e8752c76781cf6703b5a236749a...

### 🟡 MEDIUM - aiohttp (3.5.3)

**Vulnerability ID:** `CVE-2026-47265`

**Fixed Versions:** 3.14.0

**Description:** ### Summary  Cookies set with the `cookies` parameter on requests are sent after following a cross-origin redirect.  ### Impact  If a developer uses the `cookies` parameter on a per-request basis then sensitive data might be leaked to an attacker if they manage to control a redirect.  ### Workaround  If unable to upgrade, using a `Cookie` header in the `headers` parameter is not vulnerable.  -----  Patch: https://github.com/aio-libs/aiohttp/commit/f54c40851b0d6c4bbdab97ba518a223adda32478

### 🟡 MEDIUM - idna (2.8)

**Vulnerability ID:** `CVE-2026-45409`

**Fixed Versions:** 3.15

**Description:** This is the same issue as CVE-2024-3651, however the original remediation in 2024 was not a complete fix. Payloads such as `"\u0660" * N` or `"\u30fb" * N + "\u6f22"` utilize the `valid_contexto` function prior to length rejection, and for high values of `N` will take a long time to process.  ### Impact A specially crafted argument to the `idna.encode()` function could consume significant resources. This may lead to a denial-of-service.  ### Patches Starting in version 3.14, the function rejects...

### 🟡 MEDIUM - jinja2 (2.10)

**Vulnerability ID:** `CVE-2024-22195`

**Fixed Versions:** 3.1.3

**Description:** The `xmlattr` filter in affected versions of Jinja accepts keys containing spaces. XML/HTML attributes cannot contain spaces, as each would then be interpreted as a separate attribute. If an application accepts keys (as opposed to only values) as user input, and renders these in pages that other users see as well, an attacker could use this to inject other attributes and perform XSS. Note that accepting keys as user input is not common or a particularly intended use case of the `xmlattr` filter,...

### 🟡 MEDIUM - jinja2 (2.10)

**Vulnerability ID:** `CVE-2024-34064`

**Fixed Versions:** 3.1.4

**Description:** The `xmlattr` filter in affected versions of Jinja accepts keys containing non-attribute characters. XML/HTML attributes cannot contain spaces, `/`, `>`, or `=`, as each would then be interpreted as starting a separate attribute. If an application accepts keys (as opposed to only values) as user input, and renders these in pages that other users see as well, an attacker could use this to inject other attributes and perform XSS. The fix for the previous GHSA-h5c8-rqwp-cp95 CVE-2024-22195 only add...

### 🟡 MEDIUM - jinja2 (2.10)

**Vulnerability ID:** `CVE-2024-56326`

**Fixed Versions:** 3.1.5

**Description:** An oversight in how the Jinja sandboxed environment detects calls to `str.format` allows an attacker that controls the content of a template to execute arbitrary Python code.  To exploit the vulnerability, an attacker needs to control the content of a template. Whether that is the case depends on the type of application using Jinja. This vulnerability impacts users of applications which execute untrusted templates.  Jinja's sandbox does catch calls to `str.format` and ensures they don't escape t...

### 🟡 MEDIUM - jinja2 (2.10)

**Vulnerability ID:** `CVE-2025-27516`

**Fixed Versions:** 3.1.6

**Description:** An oversight in how the Jinja sandboxed environment interacts with the `|attr` filter allows an attacker that controls the content of a template to execute arbitrary Python code.  To exploit the vulnerability, an attacker needs to control the content of a template. Whether that is the case depends on the type of application using Jinja. This vulnerability impacts users of applications which execute untrusted templates.  Jinja's sandbox does catch calls to `str.format` and ensures they don't esca...

---

## Prioritized Action Items

Based on severity and exploitability, address these findings in order:

- **[HIGH] sqli/dao/user.py:41** - Use of weak MD5 hash for security. Consider usedforsecurity=False
- **[HIGH] sqli/dao/student.py:45** - Avoiding SQL string concatenation: untrusted input concatenated with raw SQL query can result in SQL
- **[HIGH] aiohttp** - Upgrade to 3.7.4: CVE-2021-21330
- **[HIGH] aiohttp** - Upgrade to 3.9.2: CVE-2024-23334
- **[HIGH] aiohttp** - Upgrade to 3.8.5: CVE-2023-37276
- **[HIGH] aiohttp** - Upgrade to 3.9.0: CVE-2023-49081
- **[HIGH] aiohttp** - Upgrade to 3.9.0: CVE-2023-49082
- **[HIGH] aiohttp** - Upgrade to 3.9.2: CVE-2024-23829
- **[HIGH] aiohttp** - Upgrade to 3.8.6: CVE-2023-47627
- **[HIGH] aiohttp** - Upgrade to 3.8.0: CVE-2023-47641
- **[HIGH] idna** - Upgrade to 3.7: CVE-2024-3651
- **[HIGH] jinja2** - Upgrade to 2.11.3: CVE-2020-28493
- **[HIGH] jinja2** - Upgrade to 2.10.1: CVE-2019-10906
- **[HIGH] pyjwt** - Upgrade to 2.13.0: CVE-2026-48526
- **[HIGH] pyjwt** - Upgrade to 2.13.0: CVE-2026-48522
- **[HIGH] pyjwt** - Upgrade to 2.13.0: CVE-2026-48524
- **[HIGH] pyjwt** - Upgrade to 2.13.0: CVE-2026-48525
- **[MEDIUM] sqli/dao/student.py:42** - Possible SQL injection vector through string-based query construction.
- **[MEDIUM] aiohttp** - Upgrade to 3.13.4: CVE-2026-34515
- **[MEDIUM] aiohttp** - Upgrade to 3.13.4: CVE-2026-34513
- **[MEDIUM] aiohttp** - Upgrade to 3.13.4: CVE-2026-34516
- **[MEDIUM] aiohttp** - Upgrade to 3.8.6: GHSA-pjjw-qhg8-p2p9
- **[MEDIUM] aiohttp** - Upgrade to 3.13.4: CVE-2026-34517
- **[MEDIUM] aiohttp** - Upgrade to 3.13.4: CVE-2026-34519
- **[MEDIUM] aiohttp** - Upgrade to 3.13.4: CVE-2026-34518
- **[MEDIUM] aiohttp** - Upgrade to 3.13.4: CVE-2026-34520
- **[MEDIUM] aiohttp** - Upgrade to 3.9.4: CVE-2024-27306
- **[MEDIUM] aiohttp** - Upgrade to 3.9.4: CVE-2024-30251
- **[MEDIUM] aiohttp** - Upgrade to 3.13.4: CVE-2026-34525
- **[MEDIUM] aiohttp** - Upgrade to 3.10.11: CVE-2024-52304

---

## Remediation Checklist

Use this checklist to track remediation progress:

### Bandit
[ ] **sqli/dao/user.py:41** - B324: Use of weak MD5 hash for security. Consider usedforsecurity=...
[ ] **sqli/dao/student.py:42** - B608: Possible SQL injection vector through string-based query con...

### Semgrep
[ ] **sqli/dao/student.py:45** - python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query: Avoiding SQL string concatenation: untrusted input concatena...
[ ] **docker-compose.yml:11** - yaml.docker-compose.security.no-new-privileges.no-new-privileges: Service 'redis' allows for privilege escalation via setuid o...
[ ] **docker-compose.yml:11** - yaml.docker-compose.security.writable-filesystem-service.writable-filesystem-service: Service 'redis' is running with a writable root filesystem. ...
[ ] **sqli/dao/student.py:45** - python.lang.security.audit.formatted-sql-query.formatted-sql-query: Detected possible formatted SQL query. Use parameterized que...
[ ] **sqli/dao/user.py:41** - python.lang.security.audit.md5-used-as-password.md5-used-as-password: It looks like MD5 is used as a password hash. MD5 is not con...
[ ] **sqli/static/js/materialize.js:565** - javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp: RegExp() called with a `t` function argument, this might all...
[ ] **sqli/static/js/materialize.js:645** - javascript.lang.security.audit.unsafe-formatstring.unsafe-formatstring: Detected string concatenation with a non-literal variable in...
[ ] **sqli/static/js/materialize.js:661** - javascript.lang.security.audit.unsafe-formatstring.unsafe-formatstring: Detected string concatenation with a non-literal variable in...
[ ] **sqli/static/js/materialize.js:699** - javascript.lang.security.audit.unsafe-formatstring.unsafe-formatstring: Detected string concatenation with a non-literal variable in...

### Dependencies
[ ] **aiohttp==3.5.3** -> **aiohttp>=3.7.4** (PYSEC-2021-76)
[ ] **aiohttp==3.5.3** -> **aiohttp>=3.7.4** (PYSEC-2021-76)
[ ] **aiohttp==3.5.3** -> **aiohttp>=3.9.2** (PYSEC-2024-24)
[ ] **aiohttp==3.5.3** -> **aiohttp>=3.8.5** (PYSEC-2023-120)
[ ] **aiohttp==3.5.3** -> **aiohttp>=3.9.0** (PYSEC-2023-250)
[ ] **aiohttp==3.5.3** -> **aiohttp>=3.9.0** (PYSEC-2023-251)
[ ] **aiohttp==3.5.3** -> **aiohttp>=3.9.2** (PYSEC-2024-24)
[ ] **aiohttp==3.5.3** -> **aiohttp>=3.9.2** (PYSEC-2024-26)
[ ] **aiohttp==3.5.3** -> **aiohttp>=3.8.6** (PYSEC-2023-246)
[ ] **aiohttp==3.5.3** -> **aiohttp>=3.8.6** (PYSEC-2023-246)
[ ] **aiohttp==3.5.3** -> **aiohttp>=3.8.0** (PYSEC-2023-247)
[ ] **aiohttp==3.5.3** -> **aiohttp>=3.9.0** (PYSEC-2023-251)
[ ] **aiohttp==3.5.3** -> **aiohttp>=3.9.0** (PYSEC-2023-250)
[ ] **aiohttp==3.5.3** -> **aiohttp>=3.9.2** (PYSEC-2024-26)
[ ] **idna==2.8** -> **idna>=3.7** (PYSEC-2024-60)
[ ] **idna==2.8** -> **idna>=3.7** (PYSEC-2024-60)
[ ] **jinja2==2.10** -> **jinja2>=2.11.3** (PYSEC-2021-66)
[ ] **jinja2==2.10** -> **jinja2>=2.10.1** (PYSEC-2019-217)
[ ] **pyjwt==2.12.1** -> **pyjwt>=2.13.0** (PYSEC-2026-179)
[ ] **pyjwt==2.12.1** -> **pyjwt>=2.13.0** (PYSEC-2026-175)
[ ] **pyjwt==2.12.1** -> **pyjwt>=2.13.0** (PYSEC-2026-177)
[ ] **pyjwt==2.12.1** -> **pyjwt>=2.13.0** (PYSEC-2026-178)
[ ] **aiohttp==3.5.3** -> **aiohttp>=3.13.4** (CVE-2026-34515)
[ ] **aiohttp==3.5.3** -> **aiohttp>=3.13.4** (CVE-2026-34513)
[ ] **aiohttp==3.5.3** -> **aiohttp>=3.13.4** (CVE-2026-34516)
[ ] **aiohttp==3.5.3** -> **aiohttp>=3.8.6** (GHSA-pjjw-qhg8-p2p9)
[ ] **aiohttp==3.5.3** -> **aiohttp>=3.13.4** (CVE-2026-34517)
[ ] **aiohttp==3.5.3** -> **aiohttp>=3.13.4** (CVE-2026-34519)
[ ] **aiohttp==3.5.3** -> **aiohttp>=3.13.4** (CVE-2026-34518)
[ ] **aiohttp==3.5.3** -> **aiohttp>=3.13.4** (CVE-2026-34520)
[ ] **aiohttp==3.5.3** -> **aiohttp>=3.9.4** (CVE-2024-27306)
[ ] **aiohttp==3.5.3** -> **aiohttp>=3.9.4** (CVE-2024-30251)
[ ] **aiohttp==3.5.3** -> **aiohttp>=3.13.4** (CVE-2026-34525)
[ ] **aiohttp==3.5.3** -> **aiohttp>=3.10.11** (CVE-2024-52304)
[ ] **aiohttp==3.5.3** -> **aiohttp>=3.12.14** (CVE-2025-53643)
[ ] **aiohttp==3.5.3** -> **aiohttp>=3.13.3** (CVE-2025-69223)
[ ] **aiohttp==3.5.3** -> **aiohttp>=3.13.3** (CVE-2025-69224)
[ ] **aiohttp==3.5.3** -> **aiohttp>=3.13.3** (CVE-2025-69228)
[ ] **aiohttp==3.5.3** -> **aiohttp>=3.13.3** (CVE-2025-69229)
[ ] **aiohttp==3.5.3** -> **aiohttp>=3.13.3** (CVE-2025-69230)
[ ] **aiohttp==3.5.3** -> **aiohttp>=3.13.3** (CVE-2025-69226)
[ ] **aiohttp==3.5.3** -> **aiohttp>=3.13.3** (CVE-2025-69227)
[ ] **aiohttp==3.5.3** -> **aiohttp>=3.13.3** (CVE-2025-69225)
[ ] **aiohttp==3.5.3** -> **aiohttp>=3.13.4** (CVE-2026-22815)
[ ] **aiohttp==3.5.3** -> **aiohttp>=3.13.4** (CVE-2026-34514)
[ ] **aiohttp==3.5.3** -> **aiohttp>=3.14.0** (CVE-2026-34993)
[ ] **aiohttp==3.5.3** -> **aiohttp>=3.14.0** (CVE-2026-47265)
[ ] **idna==2.8** -> **idna>=3.15** (CVE-2026-45409)
[ ] **jinja2==2.10** -> **jinja2>=3.1.3** (CVE-2024-22195)
[ ] **jinja2==2.10** -> **jinja2>=3.1.4** (CVE-2024-34064)
[ ] **jinja2==2.10** -> **jinja2>=3.1.5** (CVE-2024-56326)
[ ] **jinja2==2.10** -> **jinja2>=3.1.6** (CVE-2025-27516)

---

*This triage prompt was automatically generated by the security scan workflow.*