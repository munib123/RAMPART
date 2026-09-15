# djshop-dev — planted vulnerabilities (answer key, DEV split)

The Django counterpart of ShopFast, built for one question: **do the four SAST-blind locator
rules transfer from Flask to Django when only the vocabulary changes?** Every SAST-blind
weakness appears as a vulnerable function *and* as the fix the Django documentation
prescribes. The fixed twins are `safe` rows in `bench/keys/djshop-dev.key.jsonl`: a locator that
fires on them is charged a `bait_fp`, and the *reason* it fires (a missing token vs. a guard that
lives in another file or on a class) is the finding the thesis is after.

This is the **DEV** split: the rules and packs may be run against it while iterating. The
**HELD-OUT** split (`testbeds/djshop-heldout`) is run once, at the end. Both were authored and
frozen (`FREEZE.json`) before `django.json` existed.

## SAST-blind (the four locator rules)

| # | Vulnerability | CWE | Where | Fixed twin(s) | Why the twin is safe |
|---|---|---|---|---|---|
| 1 | IDOR: `get_object_or_404(Order, pk=…)` with no owner scope | CWE-639 | `views.order_detail` | 101 `order_detail_safe` | `…, user=request.user` scopes the lookup |
| 2 | IDOR: `Order.objects.get(pk=…)` behind `@login_required` only | CWE-639 | `views.invoice_pdf` | 102 `invoice_pdf_safe` | explicit `user_id != request.user.id → PermissionDenied` |
| 3 | IDOR in a DRF action: `permission_classes=[IsAuthenticated]` proves login, not ownership | CWE-639 | `api.OrderViewSet.cancel` | 103 `OrderViewSet.receipt` | `self.check_object_permissions(request, order)` |
| 4 | IDOR despite `IsOwner` on the class: `Model.objects.get()` bypasses `get_object()`, so the object permission never runs | CWE-639 | `api.OrderNoteViewSet.history` | 104 `OrderNoteViewSet.retrieve` | `self.get_object()` applies the class-level `IsOwner` (guard-as-configuration) |
| 5 | Mass assignment: `setattr(profile, k, v)` for every POST key | CWE-915 | `views.profile_update` | 105 `profile_update_safe` | `ModelForm` with `Meta.fields` (allow-list in forms.py) |
| 6 | Mass assignment: `.update(**request.POST.dict())` | CWE-915 | `views.address_update` | 106 `address_update_safe` | in-view `allowed_fields` filter |
| 7 | Unchecked quantity: `price * int(request.POST["quantity"])`, no lower bound | CWE-840 | `views.add_to_cart` | 107 `add_to_cart_form`, 108 `add_to_cart_safe` | 107: `IntegerField(min_value=1)` in forms.py (bound in another file); 108: inline `if qty <= 0` |
| 8 | TOCTOU: `if product.stock >= qty: product.stock -= qty; product.save()` | CWE-362 | `views.checkout` | 109 `checkout_safe`, 110 `checkout_atomic_update` | 109: `transaction.atomic()` + `select_for_update()`; 110: conditional `UPDATE … F("stock") - qty`, no read-modify-write |

## Pattern-scanner territory (baseline for the bandit / semgrep arms)

| # | Vulnerability | CWE | Where | Twin |
|---|---|---|---|---|
| 9 | SQL injection via `Manager.raw()` f-string | CWE-89 | `views.search` | 111 `search_safe` (ORM `filter(name__icontains=q)`) |
| 10 | Reflected XSS via `mark_safe()` on a query parameter | CWE-79 | `views.flash_message` | — |
| 11 | Hard-coded `SECRET_KEY` | CWE-798 | `djshop/settings.py` | — |
| 12 | `DEBUG = True` | CWE-489 | `djshop/settings.py` | — |

## What the plan predicts (recorded before any run)

- With `_base` / `flask-sqlite3`: rows 1–4 (IDOR) mostly **missed** — `get_object_or_404` and
  `get` are not in those packs' `orm_read_calls`; row 8 (TOCTOU) **missed** — `save()` is not a
  write token; rows 5 and 7 **found** (`items`/`setattr`, `price * qty` are framework-neutral).
- With a Django pack: 1–4 and 8 become reachable by vocabulary alone.
- Fixed twins that a per-method token search **cannot** clear, whatever the pack: 104 (guard is
  a class attribute), 105 (allow-list is in forms.py), 107 (bound is in forms.py). Those are
  structural, and they are P7's job, not a pack's.
