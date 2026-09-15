# djbilling (HELD-OUT split)

The held-out half of RAMPART's Django testbed: wallets, invoices, refunds, coupons and support
tickets on Django 5 + DRF. Same weakness classes as `djshop-dev`, different code.

> Intentionally insecure. Never deploy it. Catalogue in [`VULNERABILITIES.md`](VULNERABILITIES.md).

**Protocol.** This split is evaluated **once**, after `django.json` has been authored from
framework documentation. Do not run the bench against it while developing rules or packs;
use `djshop-dev`. `FREEZE.json` holds the tree hash from the moment it was frozen, and
`bench/run.py` records every run of a held-out benchmark in `bench/runs/heldout.log`.

| File | Responsibility |
|---|---|
| `djbilling/settings.py`, `djbilling/urls.py` | project config (three planted config bugs) |
| `billing/models.py` | Wallet, Invoice, InvoiceLine, Payout, Coupon, Ticket, Attachment |
| `billing/views.py` | function views: every SAST-blind bug and its fixed twin(s) |
| `billing/api.py` | DRF WalletViewSet: queryset-scoped ownership and the actions that bypass it |
| `billing/forms.py`, `billing/serializers.py` | where the documented fixes put the guard |
