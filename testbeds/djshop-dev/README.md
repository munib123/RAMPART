# djshop (DEV split)

A small Django 5 + DRF storefront used as a **test target for RAMPART's Joern/CPG phase**:
products, cart, checkout, orders, invoices, a profile, and a small REST API.

> Intentionally insecure. Never deploy it. The planted weaknesses, each next to the fix the
> Django documentation prescribes, are catalogued in [`VULNERABILITIES.md`](VULNERABILITIES.md).

| File | Responsibility |
|---|---|
| `djshop/settings.py`, `djshop/urls.py` | project config (with two planted config bugs) |
| `shop/models.py` | Product, Profile, Address, Cart, CartItem, Order, OrderNote |
| `shop/views.py` | function views: every SAST-blind bug and its fixed twin(s) |
| `shop/api.py` | DRF ViewSets: the guard-as-configuration cases |
| `shop/forms.py`, `shop/serializers.py`, `shop/permissions.py` | where the *documented* fixes put the guard - another file |

It is a static target: nothing here needs to run. `FREEZE.json` records the tree hash at the
moment the split was frozen; `bench/tests/test_freeze.py` fails if any file changes afterwards.

```
backend\.venv\Scripts\python.exe -m bench.run --backend joern --benchmark djshop-dev --pack _base
backend\.venv\Scripts\python.exe -m bench.run --backend joern --benchmark djshop-dev --pack django
```
