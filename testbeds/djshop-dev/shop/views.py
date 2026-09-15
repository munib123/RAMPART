"""shop views - the DEV split of the RAMPART Django testbed.

Every SAST-blind weakness appears twice: once as written by a hurried developer, once as the
Django documentation says to write it. The fixed twins are what a locator has to stay quiet on.
See VULNERABILITIES.md for the catalogue. This code is intentionally insecure; never deploy it.
"""
from decimal import Decimal

from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.db.models import F
from django.http import HttpResponse, HttpResponseBadRequest, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils.safestring import mark_safe
from django.views.decorators.http import require_POST

from .forms import AddToCartForm, ProfileForm
from .models import Address, Cart, CartItem, Order, Product


# --------------------------------------------------------------------------------------- #
# IDOR: reading an object by its id without checking who owns it
# --------------------------------------------------------------------------------------- #

@login_required
def order_detail(request, order_id):
    """Any logged-in user can read any order: the lookup is by primary key alone."""
    order = get_object_or_404(Order, pk=order_id)
    return render(request, "shop/order_detail.html", {"order": order})


@login_required
def order_detail_safe(request, order_id):
    """The documented fix: scope the lookup to the requesting user."""
    order = get_object_or_404(Order, pk=order_id, user=request.user)
    return render(request, "shop/order_detail.html", {"order": order})


@login_required
def invoice_pdf(request, order_id):
    """Same defect through Manager.get(): the id comes from the URL, the owner is never consulted."""
    order = Order.objects.get(pk=order_id)
    pdf = _render_invoice(order)
    return HttpResponse(pdf, content_type="application/pdf")


@login_required
def invoice_pdf_safe(request, order_id):
    """Fixed by an explicit ownership comparison that raises 403."""
    order = Order.objects.get(pk=order_id)
    if order.user_id != request.user.id:
        raise PermissionDenied("not your order")
    pdf = _render_invoice(order)
    return HttpResponse(pdf, content_type="application/pdf")


def _render_invoice(order):
    lines = [f"Invoice for order {order.pk}", f"Status: {order.status}", f"Total: {order.total}"]
    return "\n".join(lines).encode()


# --------------------------------------------------------------------------------------- #
# Mass assignment: writing every submitted field into a model
# --------------------------------------------------------------------------------------- #

@login_required
@require_POST
def profile_update(request):
    """Every POSTed key becomes an attribute: is_vendor=1 or store_credit=9999 both work."""
    profile = request.user.profile
    for field, value in request.POST.items():
        setattr(profile, field, value)
    profile.save()
    return redirect("profile_update")


@login_required
@require_POST
def profile_update_safe(request):
    """The documented fix: a ModelForm whose Meta.fields is the allow-list (see forms.py)."""
    profile = request.user.profile
    form = ProfileForm(request.POST, instance=profile)
    if form.is_valid():
        form.save()
        return redirect("profile_update_safe")
    return render(request, "shop/profile.html", {"form": form}, status=400)


@login_required
@require_POST
def address_update(request, address_id):
    """Ownership is checked, but the update takes the whole POST body: verified=1 is one field away."""
    address = get_object_or_404(Address, pk=address_id, user=request.user)
    Address.objects.filter(pk=address.pk).update(**request.POST.dict())
    return JsonResponse({"ok": True})


@login_required
@require_POST
def address_update_safe(request, address_id):
    """Fixed in the view itself: only the allowed fields survive the filter."""
    address = get_object_or_404(Address, pk=address_id, user=request.user)
    allowed_fields = {"line1", "line2", "city"}
    data = {k: v for k, v in request.POST.items() if k in allowed_fields}
    Address.objects.filter(pk=address.pk).update(**data)
    return JsonResponse({"ok": True})


# --------------------------------------------------------------------------------------- #
# Unchecked quantity: money computed from a caller-supplied count with no lower bound
# --------------------------------------------------------------------------------------- #

@login_required
@require_POST
def add_to_cart(request, product_id):
    """quantity=-3 yields a negative line total and, at checkout, a credit."""
    product = get_object_or_404(Product, pk=product_id)
    cart, _ = Cart.objects.get_or_create(user=request.user)
    qty = int(request.POST.get("quantity", 1))
    line_total = product.price * qty
    CartItem.objects.create(cart=cart, product=product, quantity=qty, line_total=line_total)
    return redirect("checkout")


@login_required
@require_POST
def add_to_cart_form(request, product_id):
    """The documented fix: the bound is declared on the form field (min_value=1 in forms.py).
    The view that does the arithmetic contains no comparison at all."""
    product = get_object_or_404(Product, pk=product_id)
    cart, _ = Cart.objects.get_or_create(user=request.user)
    form = AddToCartForm(request.POST)
    if not form.is_valid():
        return HttpResponseBadRequest(form.errors.as_json())
    qty = form.cleaned_data["quantity"]
    line_total = product.price * qty
    CartItem.objects.create(cart=cart, product=product, quantity=qty, line_total=line_total)
    return redirect("checkout")


@login_required
@require_POST
def add_to_cart_safe(request, product_id):
    """Fixed inline: an explicit lower bound before the arithmetic."""
    product = get_object_or_404(Product, pk=product_id)
    cart, _ = Cart.objects.get_or_create(user=request.user)
    qty = int(request.POST.get("quantity", 1))
    if qty <= 0:
        return HttpResponseBadRequest("quantity must be positive")
    line_total = product.price * qty
    CartItem.objects.create(cart=cart, product=product, quantity=qty, line_total=line_total)
    return redirect("checkout")


# --------------------------------------------------------------------------------------- #
# TOCTOU: check the stock, then write it, with nothing holding the row in between
# --------------------------------------------------------------------------------------- #

@login_required
@require_POST
def checkout(request):
    """Two concurrent checkouts both see stock >= quantity and both decrement it."""
    cart = get_object_or_404(Cart, user=request.user)
    order = Order.objects.create(user=request.user)
    total = Decimal("0")
    for item in cart.items.select_related("product"):
        product = item.product
        if product.stock >= item.quantity:
            product.stock -= item.quantity
            product.save()
            total += item.line_total
    order.total = total
    order.save()
    cart.items.all().delete()
    return redirect("order_detail", order_id=order.pk)


@login_required
@require_POST
def checkout_safe(request):
    """The documented fix: a transaction plus select_for_update() holds the row through the check."""
    cart = get_object_or_404(Cart, user=request.user)
    with transaction.atomic():
        order = Order.objects.create(user=request.user)
        total = Decimal("0")
        for item in cart.items.select_related("product"):
            product = Product.objects.select_for_update().get(pk=item.product_id)
            if product.stock >= item.quantity:
                product.stock -= item.quantity
                product.save()
                total += item.line_total
        order.total = total
        order.save()
        cart.items.all().delete()
    return redirect("order_detail", order_id=order.pk)


@login_required
@require_POST
def checkout_atomic_update(request):
    """The other documented fix: no read-modify-write at all - a conditional UPDATE with F()."""
    cart = get_object_or_404(Cart, user=request.user)
    order = Order.objects.create(user=request.user)
    total = Decimal("0")
    for item in cart.items.select_related("product"):
        updated = Product.objects.filter(pk=item.product_id, stock__gte=item.quantity).update(
            stock=F("stock") - item.quantity)
        if updated:
            total += item.line_total
    order.total = total
    order.save()
    cart.items.all().delete()
    return redirect("order_detail", order_id=order.pk)


# --------------------------------------------------------------------------------------- #
# Pattern-scanner territory: here so the bandit/semgrep arms have a Django baseline too
# --------------------------------------------------------------------------------------- #

def search(request):
    """SQL injection through Manager.raw() with an f-string."""
    q = request.GET.get("q", "")
    products = Product.objects.raw(f"SELECT * FROM shop_product WHERE name LIKE '%{q}%'")
    return render(request, "shop/search.html", {"products": list(products), "q": q})


def search_safe(request):
    """The ORM lookup that search() should have used. Precision bait for the pattern arms."""
    q = request.GET.get("q", "")
    products = Product.objects.filter(name__icontains=q)
    return render(request, "shop/search.html", {"products": list(products), "q": q})


def flash_message(request):
    """Reflected XSS: mark_safe() on a query-string value."""
    msg = mark_safe(request.GET.get("msg", ""))
    return HttpResponse(f"<div class='flash'>{msg}</div>")
