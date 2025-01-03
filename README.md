# Remediations for Typical Vulnerable Code

This document highlights common OWASP vulnerabilities, shows example vulnerable code, and provides guidance for remediation. It also explains how to detect the **source** (where data enters the application) and the **sink** (where the application uses that data in a potentially unsafe manner).

## Table of Contents

1. [Overview](#overview)
2. [SQL Injection](#sql-injection)
    - [Sample Vulnerable Code](#sample-vulnerable-code)
    - [Source and Sink Explained](#source-and-sink-explained)
    - [Secure Remediation](#secure-remediation)
3. [Cross-Site Scripting (XSS)](#cross-site-scripting-xss)
    - [Sample Vulnerable Code](#sample-vulnerable-code-1)
    - [Source and Sink Explained](#source-and-sink-explained-1)
    - [Secure Remediation](#secure-remediation-1)
4. [Command Injection](#command-injection)
    - [Sample Vulnerable Code](#sample-vulnerable-code-2)
    - [Source and Sink Explained](#source-and-sink-explained-2)
    - [Secure Remediation](#secure-remediation-2)
5. [Additional OWASP Concerns](#additional-owasp-concerns)
6. [Using Static Code Analysis (Fortify SCA)](#using-static-code-analysis-fortify-sca)
    - [Identifying Sources and Sinks in Fortify](#identifying-sources-and-sinks-in-fortify)
    - [Remediation Workflow](#remediation-workflow)
7. [References](#references)

---

## Overview

Many security vulnerabilities arise from how user-supplied data enters an application (the **source**) and how it’s ultimately processed or used (the **sink**). 

- **Source**: The place where data enters the application, such as `Request.QueryString`, form fields, or API calls.  
- **Sink**: The place where data is used in a way that could compromise security if not properly sanitized or validated, such as in a SQL query, dynamic command, or rendered output on a webpage.

**Goal**: Mitigate risks by validating, encoding, or sanitizing untrusted data before it reaches a dangerous sink.

---

## SQL Injection

### Sample Vulnerable Code

```csharp
// Vulnerable: directly concatenating user input into a SQL query
string userName = Request.QueryString["user"];
string query = "SELECT * FROM Users WHERE UserName = '" + userName + "'";
// Potentially unsafe execution
SqlCommand cmd = new SqlCommand(query, connection);
SqlDataReader reader = cmd.ExecuteReader();
```

Why is This Vulnerable?
The userName parameter is taken directly from the query string without validation or sanitization.
Attackers can manipulate the userName variable to inject malicious SQL (e.g., john' OR '1'='1).
Source and Sink Explained
Source: Request.QueryString["user"] is the untrusted input.
Sink: The string concatenation used in the WHERE clause of the SQL statement.
Secure Remediation
Use parameterized queries or stored procedures:

```csharp
string userName = Request.QueryString["user"];
string query = "SELECT * FROM Users WHERE UserName = @UserName";
using (SqlCommand cmd = new SqlCommand(query, connection))
{
    cmd.Parameters.AddWithValue("@UserName", userName);
    SqlDataReader reader = cmd.ExecuteReader();
    // Process results
}
```
Key Takeaways:

Always parameterize user inputs in SQL queries.
Never concatenate untrusted data directly into query strings.

