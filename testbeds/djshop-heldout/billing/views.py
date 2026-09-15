"""billing views - the HELD-OUT split of the RAMPART Django testbed.

Same four weakness classes as the DEV split, different domain, different idioms. This file is
evaluated once. This code is intentionally insecure; never deploy it.
"""
import json
import subprocess
from decimal import Decimal

from django.contrib.auth.decorators import login_required
from django.db import connection, transaction
from django.db.models import F
from django.http import (FileResponse, Http404, HttpResponse, HttpResponseBadRequest,
                         HttpResponseForbidden, JsonResponse)
from django.shortcuts import get_object_or_404, redirect, render
from django.template import Context, Template
from django.views.decorators.http import require_POST

from .forms import RefundForm, TicketForm
from .models import Attachment, Coupon, Invoice, InvoiceLine, Payout, Ticket, Wallet

BONUS_RATE = Decimal("0.05")


# --------------------------------------------------------------------------------------- #
# IDOR
# --------------------------------------------------------------------------------------- #

@login_required
def invoice_detail(request, invoice_id):
    """Looks up the invoice by id alone; every customer can read every invoice."""
    invoice = Invoice.objects.filter(pk=invoice_id).first()
    if invoice is None:
        raise Http404("no such invoice")
    return render(request, "billing/invoice.html", {"invoice": invoice, "lines": invoice.lines.all()})


@login_required
def invoice_detail_safe(request, invoice_id):
    """Fixed through the reverse relation: only the caller's own invoices are searched."""
    invoice = request.user.invoices.filter(pk=invoice_id).first()
    if invoice is None:
        raise Http404("no such invoice")
    return render(request, "billing/invoice.html", {"invoice": invoice, "lines": invoice.lines.all()})


@login_required
def ticket_attachment(request, attachment_id):
    """Serves any customer's uploaded file to any logged-in user."""
    attachment = Attachment.objects.select_related("ticket").get(pk=attachment_id)
    return FileResponse(attachment.file.open("rb"), as_attachment=True)


@login_required
def ticket_attachment_safe(request, attachment_id):
    """Fixed with an explicit ownership check on the parent ticket."""
    attachment = Attachment.objects.select_related("ticket").get(pk=attachment_id)
    if attachment.ticket.owner_id != request.user.id:
        return HttpResponseForbidden("not your ticket")
    return FileResponse(attachment.file.open("rb"), as_attachment=True)


# --------------------------------------------------------------------------------------- #
# Mass assignment
# --------------------------------------------------------------------------------------- #

@login_required
@require_POST
def ticket_update(request, ticket_id):
    """Ownership is checked; then every key of the JSON body lands on the model, including
    priority, assigned_to and resolved."""
    ticket = get_object_or_404(Ticket, pk=ticket_id, owner=request.user)
    payload = json.loads(request.body)
    for field, value in payload.items():
        setattr(ticket, field, value)
    ticket.save()
    return JsonResponse({"id": ticket.pk, "priority": ticket.priority})


@login_required
@require_POST
def ticket_update_form(request, ticket_id):
    """The documented fix: a ModelForm whose Meta.fields (forms.py) is the allow-list."""
    ticket = get_object_or_404(Ticket, pk=ticket_id, owner=request.user)
    payload = json.loads(request.body)
    form = TicketForm(payload, instance=ticket)
    if not form.is_valid():
        return JsonResponse(form.errors, status=400)
    form.save()
    return JsonResponse({"id": ticket.pk})


@login_required
@require_POST
def ticket_update_safe(request, ticket_id):
    """Fixed inline: the writable fields are named in the view."""
    ticket = get_object_or_404(Ticket, pk=ticket_id, owner=request.user)
    payload = json.loads(request.body)
    editable_fields = ("subject", "body")
    for field in editable_fields:
        if field in payload:
            setattr(ticket, field, payload[field])
    ticket.save()
    return JsonResponse({"id": ticket.pk})


# --------------------------------------------------------------------------------------- #
# Unchecked quantity / amount
# --------------------------------------------------------------------------------------- #

@login_required
@require_POST
def refund_line(request, line_id):
    """qty=-5 credits nothing and debits the wallet; qty=1000 refunds more than was bought."""
    line = get_object_or_404(InvoiceLine, pk=line_id, invoice__customer=request.user)
    qty_returned = int(request.POST["qty"])
    refund_total = line.unit_price * qty_returned
    wallet = request.user.wallet
    wallet.balance = wallet.balance + refund_total
    wallet.save()
    return JsonResponse({"refunded": str(refund_total)})


@login_required
@require_POST
def refund_line_form(request, line_id):
    """The documented fix: RefundForm bounds qty (min_value=1, max_value=line.quantity) in forms.py."""
    line = get_object_or_404(InvoiceLine, pk=line_id, invoice__customer=request.user)
    form = RefundForm(request.POST, max_qty=line.quantity)
    if not form.is_valid():
        return JsonResponse(form.errors, status=400)
    qty_returned = form.cleaned_data["qty"]
    refund_total = line.unit_price * qty_returned
    wallet = request.user.wallet
    wallet.balance = wallet.balance + refund_total
    wallet.save()
    return JsonResponse({"refunded": str(refund_total)})


@login_required
@require_POST
def refund_line_safe(request, line_id):
    """Fixed inline with both bounds."""
    line = get_object_or_404(InvoiceLine, pk=line_id, invoice__customer=request.user)
    qty_returned = int(request.POST["qty"])
    if qty_returned < 1 or qty_returned > line.quantity:
        return HttpResponseBadRequest("qty out of range")
    refund_total = line.unit_price * qty_returned
    wallet = request.user.wallet
    wallet.balance = wallet.balance + refund_total
    wallet.save()
    return JsonResponse({"refunded": str(refund_total)})


@login_required
@require_POST
def topup_bonus(request):
    """A negative top-up amount earns a negative bonus and drains the wallet."""
    wallet = request.user.wallet
    amount = Decimal(request.POST["amount"])
    bonus = amount * BONUS_RATE
    wallet.balance = wallet.balance + amount + bonus
    wallet.save()
    return JsonResponse({"balance": str(wallet.balance), "bonus": str(bonus)})


@login_required
@require_POST
def topup_bonus_safe(request):
    wallet = request.user.wallet
    amount = Decimal(request.POST["amount"])
    if amount <= 0:
        return HttpResponseBadRequest("amount must be positive")
    bonus = amount * BONUS_RATE
    wallet.balance = wallet.balance + amount + bonus
    wallet.save()
    return JsonResponse({"balance": str(wallet.balance), "bonus": str(bonus)})


# --------------------------------------------------------------------------------------- #
# TOCTOU
# --------------------------------------------------------------------------------------- #

@login_required
@require_POST
def redeem_coupon(request, code):
    """Two requests both read redemption_count < max_redemptions before either saves."""
    coupon = Coupon.objects.get(code=code)
    if coupon.redemption_count < coupon.max_redemptions:
        coupon.redemption_count += 1
        coupon.save()
        wallet = request.user.wallet
        wallet.balance = wallet.balance + coupon.discount
        wallet.save()
        return JsonResponse({"applied": str(coupon.discount)})
    return JsonResponse({"applied": "0"}, status=409)


@login_required
@require_POST
def redeem_coupon_locked(request, code):
    """The documented fix: hold the row for the duration of the check-then-write."""
    with transaction.atomic():
        coupon = Coupon.objects.select_for_update().get(code=code)
        if coupon.redemption_count < coupon.max_redemptions:
            coupon.redemption_count += 1
            coupon.save()
            Wallet.objects.filter(owner=request.user).update(balance=F("balance") + coupon.discount)
            return JsonResponse({"applied": str(coupon.discount)})
    return JsonResponse({"applied": "0"}, status=409)


@login_required
@require_POST
def redeem_coupon_atomic(request, code):
    """The other documented fix: the check is inside the UPDATE's WHERE clause."""
    claimed = Coupon.objects.filter(code=code, redemption_count__lt=F("max_redemptions")).update(
        redemption_count=F("redemption_count") + 1)
    if not claimed:
        return JsonResponse({"applied": "0"}, status=409)
    coupon = Coupon.objects.get(code=code)
    Wallet.objects.filter(owner=request.user).update(balance=F("balance") + coupon.discount)
    return JsonResponse({"applied": str(coupon.discount)})


@login_required
@require_POST
def withdraw(request):
    """balance >= amount is checked, then written, with nothing holding the row in between."""
    wallet = request.user.wallet
    amount = Decimal(request.POST["amount"])
    if wallet.balance >= amount:
        wallet.balance -= amount
        wallet.save()
        Payout.objects.create(wallet=wallet, amount=amount)
        return JsonResponse({"balance": str(wallet.balance)})
    return HttpResponseBadRequest("insufficient funds")


@login_required
@require_POST
def withdraw_safe(request):
    """Fixed: a conditional UPDATE; the payout row is created only if the debit happened."""
    wallet = request.user.wallet
    amount = Decimal(request.POST["amount"])
    debited = Wallet.objects.filter(pk=wallet.pk, balance__gte=amount).update(balance=F("balance") - amount)
    if not debited:
        return HttpResponseBadRequest("insufficient funds")
    Payout.objects.create(wallet=wallet, amount=amount)
    return JsonResponse({"ok": True})


# --------------------------------------------------------------------------------------- #
# Pattern-scanner territory
# --------------------------------------------------------------------------------------- #

@login_required
def export_invoices(request):
    """SQL injection: the status filter is %-formatted into the query."""
    status = request.GET.get("status", "open")
    with connection.cursor() as cursor:
        cursor.execute("SELECT number, total FROM billing_invoice WHERE customer_id = %s AND status = '%s'"
                       % (request.user.id, status))
        rows = cursor.fetchall()
    body = "\n".join(f"{number},{total}" for number, total in rows)
    return HttpResponse(body, content_type="text/csv")


@login_required
def export_invoices_safe(request):
    """Parameterised. Precision bait for the pattern arms."""
    status = request.GET.get("status", "open")
    with connection.cursor() as cursor:
        cursor.execute("SELECT number, total FROM billing_invoice WHERE customer_id = %s AND status = %s",
                       [request.user.id, status])
        rows = cursor.fetchall()
    body = "\n".join(f"{number},{total}" for number, total in rows)
    return HttpResponse(body, content_type="text/csv")


@login_required
def receipt_pdf(request, invoice_id):
    """OS command injection: the id is a URL segment, the command runs through a shell."""
    invoice = get_object_or_404(Invoice, pk=invoice_id, customer=request.user)
    out = f"/tmp/receipt-{invoice.number}.pdf"
    subprocess.run(f"wkhtmltopdf http://localhost/billing/invoices/{invoice_id}/ {out}", shell=True, check=True)
    return FileResponse(open(out, "rb"), as_attachment=True)


def preview_template(request):
    """Server-side template injection: the template source comes from the query string."""
    source = request.GET.get("tpl", "Hello {{ user }}")
    html = Template(source).render(Context({"user": request.user}))
    return HttpResponse(html)
