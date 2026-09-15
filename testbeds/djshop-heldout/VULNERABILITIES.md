# djshop-heldout — planted vulnerabilities (answer key, HELD-OUT split)

The held-out half of the Django testbed: the same four SAST-blind weakness classes as
`djshop-dev`, in a billing domain (wallets, invoices, refunds, coupons, support tickets) with
idioms the DEV split does not use (`.filter().first()`, reverse relations, JSON bodies, DRF
`request.data`, `%`-formatted SQL). Authored and frozen (`FREEZE.json`) before `django.json`
existed; **evaluated once**, after the pack was written. `bench/run.py` appends every run of a
held-out benchmark to `bench/runs/heldout.log`, so a second touch is visible.

## SAST-blind

| # | Vulnerability | CWE | Where | Fixed twin(s) | Why the twin is safe |
|---|---|---|---|---|---|
| 1 | IDOR: `Invoice.objects.filter(pk=…).first()` | CWE-639 | `views.invoice_detail` | 101 `invoice_detail_safe` | reverse relation `request.user.invoices.filter(...)` scopes the search |
| 2 | IDOR: `Attachment.objects….get(pk=…)` serves any user's file | CWE-639 | `views.ticket_attachment` | 102 `ticket_attachment_safe` | `owner_id != request.user.id → HttpResponseForbidden` |
| 3 | IDOR in a DRF action: `Wallet.objects.get(pk=pk)` bypasses `get_queryset()` and moves money out of any wallet | CWE-639 | `api.WalletViewSet.transfer` | 103 `WalletViewSet.statement`, 104 `WalletViewSet.close` | 103: `self.get_object()` filters through the owner-scoped queryset (guard-as-configuration); 104: `get_object_or_404(…, owner=request.user)` |
| 4 | Mass assignment: `setattr(ticket, k, v)` for every key of a JSON body (priority, assigned_to, resolved) | CWE-915 | `views.ticket_update` | 105 `ticket_update_form`, 106 `ticket_update_safe` | 105: `ModelForm` with `Meta.fields` in forms.py; 106: inline `editable_fields` tuple |
| 5 | Mass assignment over DRF `request.data` (balance, credit_limit, frozen) | CWE-915 | `api.WalletViewSet.settings` | 107 `WalletViewSet.settings_safe` | serializer `Meta.fields` in serializers.py |
| 6 | Unchecked quantity: `unit_price * int(request.POST["qty"])` credits the wallet | CWE-840 | `views.refund_line` | 108 `refund_line_form`, 109 `refund_line_safe` | 108: `RefundForm` bounds qty in forms.py; 109: inline `< 1 or > line.quantity` |
| 7 | Unchecked amount: `amount * BONUS_RATE` with a negative amount drains the wallet | CWE-840 | `views.topup_bonus` | 110 `topup_bonus_safe` | inline `if amount <= 0` |
| 8 | TOCTOU: `if redemption_count < max_redemptions: … save()` | CWE-362 | `views.redeem_coupon` | 111 `redeem_coupon_locked`, 112 `redeem_coupon_atomic` | 111: `transaction.atomic()` + `select_for_update()`; 112: conditional `UPDATE … F()` |
| 9 | TOCTOU: `if wallet.balance >= amount: balance -= amount; save()` | CWE-362 | `views.withdraw` | 113 `withdraw_safe` | conditional `UPDATE … balance__gte=amount` |

## Pattern-scanner territory

| # | Vulnerability | CWE | Where | Twin |
|---|---|---|---|---|
| 10 | SQL injection: `%`-formatted status in `cursor.execute` | CWE-89 | `views.export_invoices` | 114 `export_invoices_safe` (parameterised) |
| 11 | OS command injection: `subprocess.run(f"…{invoice_id}…", shell=True)` | CWE-78 | `views.receipt_pdf` | — |
| 12 | Server-side template injection: `Template(request.GET["tpl"])` | CWE-1336 | `views.preview_template` | — |
| 13 | Hard-coded `SECRET_KEY` | CWE-798 | `djbilling/settings.py` | — |
| 14 | Hard-coded database password | CWE-259 | `djbilling/settings.py` | — |
| 15 | `DEBUG = True` | CWE-489 | `djbilling/settings.py` | — |
