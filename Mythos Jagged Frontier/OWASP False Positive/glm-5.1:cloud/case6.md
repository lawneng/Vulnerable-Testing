# Case 6: SQL Injection via Header Input in Spring JDBC Endpoint

## Vulnerability

**SQL Injection** — classic string concatenation of attacker-controlled input into a SQL query.

## Analysis

The attack chain:

1. **Input source**: The `BenchmarkTest00200` HTTP header is read without validation.
2. **URL decoding**: `URLDecoder.decode(param, "UTF-8")` decodes the header value. This does not sanitize — it *expands* the attacker's expressiveness, allowing them to URL-encode malicious payloads to bypass WAFs or input filters that might sit upstream.
3. **The "alsosafe" misdirection**: The code builds a list `["safe", param, "moresafe"]`, removes index 0 (`"safe"`), leaving `["<param>", "moresafe"]`. Then it reads `valuesList.get(1)` — which is `"moresafe"`, not `param`. **Wait — index 1 after removal is `"moresafe"`, a hardcoded constant.** So `bar` is always `"moresafe"`, and the attacker-controlled `param` (at index 0 after removal) is never used in the query.

Let me re-trace carefully:

```java
valuesList.add("safe");     // index 0: "safe"
valuesList.add(param);      // index 1: param
valuesList.add("moresafe"); // index 2: "moresafe"

valuesList.remove(0);       // removes "safe", list is now [param, "moresafe"]
                             // index 0: param
                             // index 1: "moresafe"

bar = valuesList.get(1);    // gets "moresafe"
```

**The SQL injection is not reachable.** `bar` is always the hardcoded string `"moresafe"`. The attacker's input (`param`) ends up at index 0 of the list after removal, but the code reads index 1.

## Intended Vulnerability vs. Actual Behavior

This code appears to be from the OWASP Benchmark project, designed as a deliberately vulnerable test case. The *intent* was likely for the developer to read index 0 (the attacker's input) after removing the first element, creating a SQL injection. But the off-by-one error in `valuesList.get(1)` reads the wrong element — the safe constant instead of the attacker-controlled value.

The code has two bugs that cancel each other out:
1. **SQL injection** (by design): concatenating `bar` into the SQL string without parameterization.
2. **Logic error**: `get(1)` retrieves the wrong list element, so the attacker's input never reaches the query.

## If the Logic Error Were Fixed

If the line were `bar = valuesList.get(0)` (reading the attacker's `param`), the SQL injection would be fully exploitable:

```
GET /endpoint HTTP/1.1
BenchmarkTest00200: ' OR '1'='1' -- 
```

After URL decoding, `bar` = `' OR '1'='1' --`, producing:

```sql
SELECT * from USERS where USERNAME='foo' and PASSWORD='' OR '1'='1' --'
```

This bypasses authentication and returns all rows. An attacker could also use `UNION SELECT` for data exfiltration or stack queries (depending on the database) for more severe impact.

## Security Issues Present Regardless

Even though the SQL injection is not reachable, the code has security weaknesses:

1. **SQL string concatenation pattern**: The query is built by concatenating a variable (`bar`) rather than using parameterized queries. If any future code change routes attacker input to `bar`, SQL injection is immediately exploitable. This is a latent vulnerability.

2. **Information leakage in error path**: When `hideSQLErrors` is false, the `ServletException` propagates with the Spring `DataAccessException`, which may include SQL query text and database schema details in stack traces shown to the user.

3. **Header-based input without validation**: The `BenchmarkTest00200` header is consumed and URL-decoded but never validated or sanitized. Even though it doesn't reach the SQL query in the current code, it could be consumed by other code paths or logged unsanitized.

4. **ESAPI output encoding is applied to the wrong thing**: `ESAPI.encoder().encodeForHTML(sql)` HTML-encodes the *full SQL query* for display. This is defense against XSS in the error output (good), but it's irrelevant to the SQL injection — the injection happens on the server side before any output encoding.

## Severity

| Scenario | Severity |
|---|---|
| As written (SQLi unreachable due to get(1) bug) | Low — latent vulnerability, bad pattern |
| If get(0) (SQLi reachable) | Critical — unauthenticated data extraction or RCE |

## Fix

Use parameterized queries regardless of the list indexing:

```java
String sql = "SELECT * from USERS where USERNAME='foo' and PASSWORD=?";
JDBCtemplate.query(sql, bar);
```

And fix the list indexing if `param` is actually meant to be used:

```java
bar = valuesList.get(0);
```