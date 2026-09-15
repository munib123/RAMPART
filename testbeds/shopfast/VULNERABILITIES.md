# ShopFast — planted vulnerabilities (answer key)

25 issues across **high / medium / low** severity and **easy → SAST-blind** difficulty.
Niche: e-commerce · Stack: Python. Use this to grade a RAMPART scan.

**Difficulty legend**
- **Easy** — a static analyser (semgrep/bandit) flags it directly.
- **Medium** — detectable, but needs data-flow or the right rule; easy for a human to miss.
- **Hard (SAST-blind)** — a *logic / business / concurrency* flaw a pattern scanner won't find; this is
  where RAMPART's LLM-verification + RAG grounding (and, later, the Joern/CPG phase) earns its keep.

## Injection & code execution

| # | Vulnerability | CWE | Severity | Difficulty | Where |
|---|---|---|---|---|---|
| 1 | SQL injection (product id, f-string) | CWE-89 | High | Easy | `db.py` · `find_product` |
| 2 | SQL injection (`ORDER BY` + LIKE concat) | CWE-89 | High | Medium | `db.py` · `search_products` |
| 3 | SQL injection (profile UPDATE, f-string) | CWE-89 | High | Medium | `orders.py` · `update_profile` |
| 4 | SQL injection (stock UPDATE) | CWE-89 | High | Easy | `cart.py` · `checkout` |
| 5 | OS command injection (receipt, `shell=True`) | CWE-78 | High | Easy | `payments.py` · `generate_receipt` |
| 6 | OS command injection (`os.system` thumbnail) | CWE-78 | High | Easy | `app.py` · `thumbnail` |
| 7 | Code injection via `eval` (discount rule) | CWE-95 | High | Medium | `catalog.py` · `apply_discount_rule` |
| 8 | Insecure deserialization (`pickle.loads` cart cookie) | CWE-502 | High | Easy | `cart.py` · `load_cart` |
| 9 | Reflected XSS / template injection | CWE-79 / 1336 | High | Medium | `app.py` · `hello` |

## Server-side request & parsing

| # | Vulnerability | CWE | Severity | Difficulty | Where |
|---|---|---|---|---|---|
| 10 | SSRF (fetch merchant `callback_url`) | CWE-918 | High | Hard | `payments.py` · `notify_webhook` |
| 11 | XXE (lxml `resolve_entities=True`) | CWE-611 | High | Medium | `payments.py` · `parse_bank_response` |
| 12 | Path traversal (invoice download) | CWE-22 | Medium | Medium | `catalog.py` · `download_invoice` |

## Authentication & secrets

| # | Vulnerability | CWE | Severity | Difficulty | Where |
|---|---|---|---|---|---|
| 13 | JWT signature not verified (`verify_signature=False`) | CWE-347 | High | Hard | `auth.py` · `verify_token` |
| 14 | Weak password hash (MD5) | CWE-327 / 916 | Medium | Easy | `auth.py` · `hash_password` |
| 15 | Insecure randomness (reset token) | CWE-330 | Medium | Medium | `auth.py` · `new_reset_token` |
| 16 | Hard-coded secrets (SECRET_KEY, JWT, API key, DB pass) | CWE-798 | Medium | Easy | `config.py` |
| 17 | Default admin credentials | CWE-1188 / 259 | Medium | Medium | `config.py` + `auth.is_admin_login` |
| 18 | Open redirect (`next` param) | CWE-601 | Medium | Medium | `app.py` · `login` |

## Configuration / transport

| # | Vulnerability | CWE | Severity | Difficulty | Where |
|---|---|---|---|---|---|
| 19 | Cleartext payment endpoint (`http://`) | CWE-319 | Medium | Easy | `config.py` · `PAYMENT_GATEWAY_URL` |
| 20 | Debug mode + bind `0.0.0.0` in prod | CWE-489 | Low | Easy | `app.py` · `__main__` |
| 21 | Permissive CORS (`*`) | CWE-942 | Low | Easy | `app.py` · `add_cors` |

## Logic / business / concurrency — the SAST-blind ones (RAMPART's target)

| # | Vulnerability | CWE | Severity | Difficulty | Where |
|---|---|---|---|---|---|
| 22 | IDOR — order lookup with no ownership check | CWE-639 / 862 | High | Hard (SAST-blind) | `orders.py` · `get_order` (`/order/<id>`) |
| 23 | Mass assignment — profile update sets any field incl. `is_admin` | CWE-915 | High | Hard (SAST-blind) | `orders.py` · `update_profile` |
| 24 | Business logic — negative quantity yields negative total (free store credit) | CWE-840 | Medium | Hard (SAST-blind) | `cart.py` · `add_item` |
| 25 | Race condition (TOCTOU) — stock check then decrement, no lock | CWE-362 | High | Hard (SAST-blind) | `cart.py` · `checkout` |

## Also present (safe / false-positive bait)

- `db.py` · `user_by_name` uses a **parameterised** query — a scanner should **not** flag it; a good
  test that RAMPART marks it *False positive / not a finding* rather than crying wolf.

---

### Rough expectation
- **Semgrep/Bandit alone** should catch most of #1–#21 (the pattern-detectable ones), miss #22–#25.
- **RAMPART** adds: confirms the real ones, grounds them in disclosed CVE/HackerOne exemplars of the
  same class, rates confidence, and (with the e-commerce scope) should weight access-control, IDOR,
  and payment-flow issues higher. #22–#25 remain the frontier for the CPG/remediation phase.
