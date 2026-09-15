from django.urls import include, path
from rest_framework.routers import DefaultRouter

from . import api, views

router = DefaultRouter()
router.register("api/wallets", api.WalletViewSet, basename="wallet")

urlpatterns = [
    path("invoices/<int:invoice_id>/", views.invoice_detail, name="invoice_detail"),
    path("invoices/<int:invoice_id>/mine/", views.invoice_detail_safe, name="invoice_detail_safe"),
    path("invoices/<int:invoice_id>/receipt.pdf", views.receipt_pdf, name="receipt_pdf"),
    path("invoices/export/", views.export_invoices, name="export_invoices"),
    path("invoices/export/safe/", views.export_invoices_safe, name="export_invoices_safe"),
    path("lines/<int:line_id>/refund/", views.refund_line, name="refund_line"),
    path("lines/<int:line_id>/refund/form/", views.refund_line_form, name="refund_line_form"),
    path("lines/<int:line_id>/refund/safe/", views.refund_line_safe, name="refund_line_safe"),
    path("wallet/topup/", views.topup_bonus, name="topup_bonus"),
    path("wallet/topup/safe/", views.topup_bonus_safe, name="topup_bonus_safe"),
    path("wallet/withdraw/", views.withdraw, name="withdraw"),
    path("wallet/withdraw/safe/", views.withdraw_safe, name="withdraw_safe"),
    path("coupons/<str:code>/redeem/", views.redeem_coupon, name="redeem_coupon"),
    path("coupons/<str:code>/redeem/locked/", views.redeem_coupon_locked, name="redeem_coupon_locked"),
    path("coupons/<str:code>/redeem/atomic/", views.redeem_coupon_atomic, name="redeem_coupon_atomic"),
    path("tickets/<int:ticket_id>/", views.ticket_update, name="ticket_update"),
    path("tickets/<int:ticket_id>/form/", views.ticket_update_form, name="ticket_update_form"),
    path("tickets/<int:ticket_id>/safe/", views.ticket_update_safe, name="ticket_update_safe"),
    path("attachments/<int:attachment_id>/", views.ticket_attachment, name="ticket_attachment"),
    path("attachments/<int:attachment_id>/safe/", views.ticket_attachment_safe, name="ticket_attachment_safe"),
    path("preview/", views.preview_template, name="preview_template"),
    path("", include(router.urls)),
]
