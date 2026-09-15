from django.conf import settings
from django.db import models


class Wallet(models.Model):
    owner = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="wallet")
    balance = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    currency = models.CharField(max_length=3, default="USD")
    # never user-writable
    frozen = models.BooleanField(default=False)
    credit_limit = models.DecimalField(max_digits=12, decimal_places=2, default=0)


class Invoice(models.Model):
    STATUS = [("open", "Open"), ("paid", "Paid"), ("void", "Void")]
    customer = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="invoices")
    number = models.CharField(max_length=20, unique=True)
    status = models.CharField(max_length=8, choices=STATUS, default="open")
    total = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    issued_at = models.DateTimeField(auto_now_add=True)


class InvoiceLine(models.Model):
    invoice = models.ForeignKey(Invoice, on_delete=models.CASCADE, related_name="lines")
    description = models.CharField(max_length=200)
    unit_price = models.DecimalField(max_digits=10, decimal_places=2)
    quantity = models.PositiveIntegerField(default=1)


class Payout(models.Model):
    wallet = models.ForeignKey(Wallet, on_delete=models.PROTECT, related_name="payouts")
    amount = models.DecimalField(max_digits=12, decimal_places=2)
    requested_at = models.DateTimeField(auto_now_add=True)


class Coupon(models.Model):
    code = models.CharField(max_length=24, unique=True)
    discount = models.DecimalField(max_digits=10, decimal_places=2)
    max_redemptions = models.PositiveIntegerField(default=1)
    redemption_count = models.PositiveIntegerField(default=0)


class Ticket(models.Model):
    PRIORITY = [("low", "Low"), ("normal", "Normal"), ("urgent", "Urgent")]
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="tickets")
    subject = models.CharField(max_length=140)
    body = models.TextField()
    # staff-controlled: a customer must not be able to set these
    priority = models.CharField(max_length=8, choices=PRIORITY, default="normal")
    assigned_to = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True,
                                    on_delete=models.SET_NULL, related_name="assigned_tickets")
    resolved = models.BooleanField(default=False)


class Attachment(models.Model):
    ticket = models.ForeignKey(Ticket, on_delete=models.CASCADE, related_name="attachments")
    file = models.FileField(upload_to="tickets/")
    uploaded_at = models.DateTimeField(auto_now_add=True)
