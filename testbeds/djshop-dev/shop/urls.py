from django.urls import include, path
from rest_framework.routers import DefaultRouter

from . import api, views

router = DefaultRouter()
router.register("api/orders", api.OrderViewSet, basename="order")
router.register("api/notes", api.OrderNoteViewSet, basename="note")

urlpatterns = [
    path("orders/<int:order_id>/", views.order_detail, name="order_detail"),
    path("orders/<int:order_id>/safe/", views.order_detail_safe, name="order_detail_safe"),
    path("orders/<int:order_id>/invoice.pdf", views.invoice_pdf, name="invoice_pdf"),
    path("orders/<int:order_id>/invoice-safe.pdf", views.invoice_pdf_safe, name="invoice_pdf_safe"),
    path("profile/", views.profile_update, name="profile_update"),
    path("profile/safe/", views.profile_update_safe, name="profile_update_safe"),
    path("addresses/<int:address_id>/", views.address_update, name="address_update"),
    path("addresses/<int:address_id>/safe/", views.address_update_safe, name="address_update_safe"),
    path("cart/add/<int:product_id>/", views.add_to_cart, name="add_to_cart"),
    path("cart/add-form/<int:product_id>/", views.add_to_cart_form, name="add_to_cart_form"),
    path("cart/add-safe/<int:product_id>/", views.add_to_cart_safe, name="add_to_cart_safe"),
    path("checkout/", views.checkout, name="checkout"),
    path("checkout/safe/", views.checkout_safe, name="checkout_safe"),
    path("checkout/atomic/", views.checkout_atomic_update, name="checkout_atomic_update"),
    path("search/", views.search, name="search"),
    path("search/safe/", views.search_safe, name="search_safe"),
    path("flash/", views.flash_message, name="flash_message"),
    path("", include(router.urls)),
]
