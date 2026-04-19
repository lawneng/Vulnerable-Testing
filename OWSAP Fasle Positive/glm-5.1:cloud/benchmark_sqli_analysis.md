# Security Analysis: BenchmarkTest00200 Servlet

## Vulnerability: SQL Injection (Critical)

### The Flow

1. **User input** is read from the `BenchmarkTest00200` HTTP header.
2. It's URL-decoded, then inserted into a list with two "safe" values.
3. The list is manipulated: index 0 (`"safe"`) is removed, shifting everything down.
4. `valuesList.get(1)` retrieves what was originally index 2 — the user-supplied `param`.
5. `param` is concatenated directly into a SQL query string with no sanitization or parameterization.

### Why the "Safe" Values Don't Help

The code attempts to obscure the user input by surrounding it with literal strings:

```java
valuesList.add("safe");       // index 0
valuesList.add(param);        // index 1
valuesList.add("moresafe");   // index 2

valuesList.remove(0);         // removes "safe", shifts indices
// valuesList is now: [param, "moresafe"]

bar = valuesList.get(1);      // gets "moresafe", NOT param
```

**The author likely intended `valuesList.get(1)` to retrieve a safe value after the remove, but `remove(0)` shifts indices by one.** The list after `remove(0)` is `[param, "moresafe"]`, so `get(1)` returns `"moresafe"` — the literal string. This means `bar` is actually the hardcoded string `"moresafe"`, not the user input.

### Two Interpretations

**If the code works as written** (and `bar = "moresafe"`): The SQL injection is inert — the user input never reaches the query. The vulnerability exists only in the code's *intent*; the bug in list indexing accidentally prevents exploitation.

**If the indexing bug is fixed** (e.g., `bar = valuesList.get(0)` to retrieve `param`): Full SQL injection. An attacker sets the `BenchmarkTest00200` header to `' OR '1'='1' --`, producing:

```sql
SELECT * from USERS where USERNAME='foo' and PASSWORD='' OR '1'='1' --'
```

This bypasses authentication and returns all rows.

### Why the Error Handling Doesn't Save It

- **`ESAPI.encoder().encodeForHTML()`** is applied to the SQL string *only for the HTML response output* — it does not affect the query execution. SQL injection happens at `batchUpdate(sql)`, before the response is written.
- **`hideSQLErrors`** only controls whether error messages are shown — it doesn't prevent the injection.

### Severity: Critical

| Factor | Assessment |
|---|---|
| **Attack vector** | HTTP header — no authentication required |
| **Impact** | Full database read access (batchUpdate doesn't return rows, but injection into DELETE/UPDATE/INSERT via stacked queries is possible depending on DB config) |
| **Exploitability** | Trivial — standard SQL injection in a header field |
| **Current state** | Accidentally mitigated by the list indexing bug, but the vulnerability is real and would activate from any code change that fixes the indexing |

## Recommended Fix

Use parameterized queries instead of string concatenation:

```java
String sql = "SELECT * from USERS where USERNAME='foo' and PASSWORD=?";
org.owasp.benchmark.helpers.DatabaseHelper.JDBCtemplate.query(sql, bar);
```

Even if the list indexing is corrected, parameterized queries make SQL injection impossible regardless of input content.