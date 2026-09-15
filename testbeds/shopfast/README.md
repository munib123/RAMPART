# ShopFast

A small e-commerce backend (Flask + SQLite) used as a **test target for RAMPART**. It models a
realistic little store: product catalog, search, cart/checkout, login and password reset, order
history, invoices, receipts, and merchant payment webhooks.

> This code is intentionally insecure. It exists only to exercise a security scanner. Do not
> deploy it. The planted weaknesses (and how hard each is to find) are catalogued in
> [`VULNERABILITIES.md`](VULNERABILITIES.md) — the answer key for grading a scan.

## Layout

| File | Responsibility |
|---|---|
| `app.py` | Flask routes wiring everything together |
| `config.py` | configuration, secrets, flags |
| `db.py` | SQLite access layer |
| `auth.py` | login, JWT session tokens, password reset |
| `catalog.py` | search, dynamic pricing, invoice download |
| `cart.py` | cart serialization + checkout |
| `orders.py` | order lookup + profile update |
| `payments.py` | charging, receipts, bank/webhook integration |

## Scanning it with RAMPART

Point RAMPART at this folder (niche: **E-commerce**, stack: **Python**):

```
D:\FYP\testbeds\shopfast
```
