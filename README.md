# red-team-ctf-writeups
Write-ups for a 3-challenge web security CTF: JWT algorithm confusion (RS256→HS256) to bypass token signature verification, blind boolean-based SQL injection to dump a SQLite secrets table, and SSRF filter bypass using decimal IP encoding to reach an internal service.

## Contents 

- [Recon](#recon)
- [1 · Vault (Auth / Crypto)](#1--vault-auth--crypto)
  - [Step 1 — Getting a guest token](#step-1--getting-a-guest-token)
  - [Step 2 — Fetching the RSA public key](#step-2--fetching-the-rsa-public-key)
  - [Step 3 — Forging an admin token](#step-3--forging-an-admin-token-algorithm-confusion)
- [2 · Ledger (Injection)](#2--ledger-injection)
  - [Step 1 — Finding the boolean oracle](#step-1--finding-the-boolean-oracle)
  - [Step 2 — Confirming the injection with sqlmap](#step-2--confirming-the-injection-with-sqlmap)
  - [Step 3 — Enumerating tables and columns](#step-3--enumerating-tables-and-columns)
  - [Step 4 — Dumping the flag](#step-4--dumping-the-flag)
- [3 · Relay (SSRF / Access)](#3--relay-ssrf--access)
  - [Step 1 — Testing the loopback filter](#step-1--testing-the-loopback-filter)
  - [Step 2 — Bypassing with decimal IP encoding](#step-2--bypassing-with-decimal-ip-encoding)
- [ Summary](#summary)


  
## RECON
### Nmap scan
To begin, I ran an Nmap scan against the target to identify open ports and running services. 
nmap -A 10.82.158.113 -Pn -T4

Results:

<img width="810" height="597" alt="image" src="https://github.com/user-attachments/assets/69fc28d0-c05f-44b7-88a5-29147330b4a9" />

Opening port 80 in the browser revealed the main CTF page, listing three independent challenges: Vault (Auth/Crypto), Ledger (Injection), and Relay (SSRF/Access).

<img width="933" height="802" alt="Screenshot 2026-07-05 151231" src="https://github.com/user-attachments/assets/2435820f-d4b7-4871-be95-0729b3f9a279" />

## 1 · Vault (Auth / Crypto)
**Challenge:** A token-gated vault. Guests can log in, but the server only grants access if the JWT's `role` is `admin`. The server reads the algorithm from the token header before deciding how to verify the signature.

### Step 1 — Getting a guest token
Logged in as guest and received a valid JWT — but its role is guest, not admin

<img width="998" height="444" alt="image" src="https://github.com/user-attachments/assets/722230ca-a3de-4967-8237-9c4d53537df1" />

### Step 2 — Fetching the RSA public key
Fetched the server's RSA public key — this is meant to verify RS256 signatures, but will be reused as an HS256 secret in the next step.

<img width="566" height="177" alt="image" src="https://github.com/user-attachments/assets/82a112e2-f88e-4133-a41e-7e94e8fda65a" />

The public key was saved locally to `pubkey.pemm` for use in the forging script.

<img width="551" height="177" alt="image" src="https://github.com/user-attachments/assets/418c9ac7-edb6-4b41-8b76-035a4430ef03" />


### Step 3 — Forging an admin token (algorithm confusion)
I installed the Python libraries I needed to work with JWTs.
<img width="837" height="187" alt="image" src="https://github.com/user-attachments/assets/3f9c982e-e117-48e2-b967-fceaf88bf236" />

PyJWT wouldn't let me use the RSA key as an HMAC secret (it has a built-in check against this), so I built the token manually instead:

- Set the header to `{"alg": "HS256", "typ": "JWT"}` instead of RS256
- Set the payload's `role` to `"admin"`
- Base64url-encoded both
- Signed them using HMAC-SHA256, with the RSA public key's raw text as the secret
- Combined header, payload, and signature into the final JWT
<img width="641" height="424" alt="image" src="https://github.com/user-attachments/assets/5b719b50-f9bb-4830-b026-54e6d1cfdb84" />

I ran the script and it generated the forged token. I then stored it directly in a `TOKEN` variable so I could pass it to `curl` in the next step.
<img width="936" height="198" alt="image" src="https://github.com/user-attachments/assets/feaedb6b-4f08-48a7-bb18-cadae640fa4d" />

### Result
I sent the forged token to the vault endpoint, and the server responded with "vault unlocked" and the flag.
<img width="688" height="65" alt="image" src="https://github.com/user-attachments/assets/159e5e3c-ee52-405d-8017-960f5798bf3a" />



## 2 · Ledger (Injection)
**Challenge:** An account-status lookup endpoint sitting behind a basic "WAF". It never returns real data — only tells you whether the account is "active" or "closed". That yes/no answer is more than enough if you're patient enough to ask the right questions.

### Step 1 — Finding the boolean oracle
First I checked the endpoint's normal behavior: sending `id=1` returned `"status":"active"`.

<img width="563" height="447" alt="Screenshot 2026-07-05 125530" src="https://github.com/user-attachments/assets/b9a2c445-4523-4ef8-838a-3e5364897d8e" />

Using a plain space in the payload got blocked by the WAF, so I replaced spaces with `%0a` (newline) — this bypassed the filter and the query went through.
Sending `id=1%0aOR%0a1=1` returned `"status":"closed"`.

<img width="548" height="308" alt="Screenshot 2026-07-05 131037" src="https://github.com/user-attachments/assets/76cce720-8ed2-44a6-b830-46e33c1e8428" />

To better understand the WAF's behavior, I tried adding an `X-Forwarded-For: 127.0.0.1` header — some WAFs treat requests with this header as "internal" and apply less scrutiny. This particular test didn't change the outcome, but it was a useful step in mapping out how the WAF behaved.

<img width="568" height="329" alt="Screenshot 2026-07-05 131448" src="https://github.com/user-attachments/assets/f970e6cd-fef3-4ab1-b25c-0b2c0b671764" />

Sending `id=1'%0aOR%0a'1'='1` (an always-true condition) returned `"status":"active"`. This confirmed the injection was working and the server was processing the query.

<img width="569" height="389" alt="Screenshot 2026-07-05 131712" src="https://github.com/user-attachments/assets/c60d6bb2-5fae-43be-a916-85ef6d50cb91" />

Sending `id=1'%0aAND%0a'1'='1` (a true condition with AND) returned `"status":"active"`. This confirmed AND-based conditions worked too — the foundation for building precise boolean-based blind SQLi payloads.

<img width="576" height="327" alt="Screenshot 2026-07-05 131824" src="https://github.com/user-attachments/assets/9dfa2ff6-b3ad-4114-baff-6a23f918e875" />

Sending `id=1'%0aAND%0a'1'='2` (a false condition) returned `"status":"closed"`. This fully confirmed the boolean-based blind SQL injection: true condition → "active", false condition → "closed".

<img width="564" height="333" alt="Screenshot 2026-07-05 131906" src="https://github.com/user-attachments/assets/a60fc406-a965-424e-a74f-06e76859d6fd" />

### Step 2 — Confirming the injection with sqlmap

I copied the original request from Burp into a `c2.txt` file so sqlmap could use it directly.

<img width="197" height="54" alt="image" src="https://github.com/user-attachments/assets/4257db0e-e6cc-4ca4-ae11-bf80531d8a3b" />

<img width="694" height="159" alt="image" src="https://github.com/user-attachments/assets/9c969029-5d27-4123-bca8-2dd3bfaba830" />

I ran sqlmap with `--tamper=space2randomblank` (a module that automatically swaps spaces for other whitespace characters) to bypass the WAF. sqlmap confirmed the `id` parameter was vulnerable to boolean-based blind SQL injection and identified the backend database as **SQLite**.

```bash
sqlmap -r c2.txt -p id --batch --technique=B \
  --tamper=space2randomblank --level=5 --risk=3 --string=active
```
<img width="1012" height="712" alt="image" src="https://github.com/user-attachments/assets/0e2dba37-f768-46e8-8c62-af6e44b79e74" />

I enumerated the tables — the database contained two tables: `accounts` and `secrets`. The name `secrets` strongly suggested that's where the flag would be.

```bash
sqlmap -r c2.txt -p id --batch --technique=B \
  --tamper=space2randomblank --level=5 --risk=3 --string=active --tables
```

<img width="999" height="695" alt="image" src="https://github.com/user-attachments/assets/a2f64f36-d5e6-42ed-a933-1aaf1452e58a" />

### Step 3 — Enumerating tables and columns

I checked the columns of the `secrets` table — it had just 2 columns: `key` (TEXT) and `val` (TEXT). This classic key-value structure suggested the flag would be stored in a row where `key='flag'`.

```bash
sqlmap -r c2.txt -p id --batch --technique=B \
  --tamper=space2randomblank --level=5 --risk=3 --string=active -T secrets --columns
```

<img width="1011" height="670" alt="image" src="https://github.com/user-attachments/assets/3155390b-51e8-4862-bbe5-f4ca1a84d102" />


### Step 4 — Dumping the flag

I dumped the full table — the `secrets` table contained a single row with `key=flag`, and its value was the flag we were looking for.

```bash
sqlmap -r c2.txt -p id --batch --technique=B \
  --tamper=space2randomblank --level=5 --risk=3 --string=active -T secrets --dump
```

<img width="1027" height="726" alt="image" src="https://github.com/user-attachments/assets/8197d150-1ea4-429c-8a8c-badc9d3c8c17" />

## 3 · Relay (SSRF / Access)

**Challenge:** A URL relay that previews links for you. It refuses to talk to itself. Make it talk to itself anyway.
### Step 1 — Testing the loopback filter
The challenge description gave a clear hint: an internal admin service runs on port `9000` and serves `/flag` only to localhost. But the blocklist only recognizes the loopback address when spelled the "obvious" way — hinting that alternate representations might slip through.
<img width="906" height="598" alt="image" src="https://github.com/user-attachments/assets/f848e943-5989-48a0-bbf5-8e16aed5c464" />

First I tried the standard loopback address (`127.0.0.1`) — as expected, the blocklist caught it immediately.

```
http://127.0.0.1:9000/flag
→ {"error":"loopback / internal hosts are blocked"}
```

<img width="659" height="174" alt="Screenshot 2026-07-05 133348" src="https://github.com/user-attachments/assets/f314a84f-0151-4ab5-a2f2-55e39aaf67b8" />


Next I tried the shorthand loopback notation (`127.1`, which is equivalent to `127.0.0.1`) — this was also blocked, meaning the filter recognized this format too.

```
http://127.1:9000/flag
→ {"error":"loopback / internal hosts are blocked"}
```
<img width="646" height="172" alt="Screenshot 2026-07-05 133414" src="https://github.com/user-attachments/assets/4a44a419-24b1-4d42-a5eb-d01193d1c171" />

### Step 2 — Bypassing with decimal IP encoding
Finally, I tried encoding the loopback address in **decimal format** (`127.0.0.1` = `2130706433`). This bypassed the blocklist — the server resolved the URL back to `127.0.0.1` when making the actual request, but the filter only performed string-level checks and didn't recognize this alternate encoding.

```
http://2130706433:9000/flag
→ {"body":"flag{...}","status":200}
```
By encoding the loopback address in decimal format, I bypassed the blocklist and reached the internal admin service on port `9000`, retrieving the flag.

<img width="677" height="153" alt="image" src="https://github.com/user-attachments/assets/2b6499e2-9785-43fb-92e9-2af0c69b7b7e" />

## Summary

In this CTF, I found and exploited 3 different web security vulnerabilities:

- **Vault**: Changed the JWT's `alg` field from RS256 to HS256, reusing the server's RSA public key as an HMAC secret to forge an admin token.
- **Ledger**: Bypassed the WAF's space filter using `%0a`, then used boolean-based blind SQL injection to dump the flag from the `secrets` table.
- **Relay**: Encoded the loopback address in decimal format (`2130706433`) to bypass the SSRF filter and reach the internal admin service.

All three challenges showed the same pattern: server-side checks often only validate the "expected" format (standard JWT algorithm, plain space character, classic `127.0.0.1` notation), but miss alternate representations that achieve the same result.


