# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in python
**Pair ID:** 4650_1
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4650_1`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```python
Lines 1-28 of the vulnerable file.

from typing import List, Optional, Tuple

import graphene
from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist, ValidationError
from django.db import transaction
from django.db.models import Prefetch

from ...account.error_codes import AccountErrorCode
from ...checkout import models
from ...checkout.error_codes import CheckoutErrorCode
from ...checkout.utils import (
    abort_order_data,
    add_promo_code_to_checkout,
    add_variant_to_checkout,
    change_billing_address_in_checkout,
    change_shipping_address_in_checkout,
    clean_checkout,
    create_order,
    get_user_checkout,
    get_valid_shipping_methods_for_checkout,
    prepare_order_data,
    recalculate_checkout_discount,
    remove_promo_code_from_checkout,
)
from ...core import analytics
from ...core.exceptions import InsufficientStock
from ...core.permissions import OrderPermissions
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -5,6 +5,7 @@
 from django.core.exceptions import ObjectDoesNotExist, ValidationError
 from django.db import transaction
 from django.db.models import Prefetch
+from graphql_jwt.exceptions import PermissionDenied
 
 from ...account.error_codes import AccountErrorCode
 from ...checkout import models
@@ -35,7 +36,7 @@
 from ...product import models as product_models
 from ...warehouse.availability import check_stock_quantity, get_available_quantity
 from ..account.i18n import I18nMixin
-from ..account.types import AddressInput, User
+from ..account.types import AddressInput
 from ..core.mutations import (
     BaseMutation,
     ClearMetaBaseMutation,
@@ -404,7 +405,14 @@
 
     class Arguments:
         checkout_id = graphene.ID(required=True, description="ID of the checkout.")
-        customer_id = graphene.ID(required=True, description="The ID of the customer.")
+        customer_id = graphene.ID(
+            required=False,
+            description=(
+                "The ID of the customer. DEPRECATED: This field is deprecated and will "
+                "be removed in Saleor 2.11. To identify a customer you should "
+                "authenticate with JWT token."
+            ),
+        )
 
     class Meta:
         description = "Sets the customer as the owner of the checkout."
@@ -412,14 +420,24 @@
         error_type_field = "checkout_errors"
 
     @classmethod
-    def perform_mutation(cls, _root, info, checkout_id, customer_id):
+    def check_permissions(cls, context):
+        return context.user.is_authenticated
+
+    @classmethod
+    def perform_mutation(cls, _root, info, checkout_id, customer_id=None):
         checkout = cls.get_node_or_error(
             info, checkout_id, only_type=Checkout, field="checkout_id"
         )
-        customer = cls.get_node_or_error(
-            info, customer_id, only_type=User, field="customer_id"
-        )
-        checkout.user = customer
+
+        # Check if provided customer_id matches with the authenticated user and raise
+        # error if it doesn't. This part can be removed when `customer_id` field is
+        # removed.
+        if customer_id:
+            current_user_id = graphene.Node.to_global_id("User", info.context.user.id)
+            if current_user_id != customer_id:
+                raise PermissionDenied()
+
+        checkout.user = info.context.user
         checkout.save(update_fields=["user", "last_change"])
         return CheckoutCustomerAttach(checkout=checkout)
 
@@ -434,12 +452,21 @@
         description = "Removes the user assigned as the owner of the checkout."
         error_type_class = CheckoutError
         error_type_field = "checkout_errors"
+
+    @classmethod
+    def check_permissions(cls, context):
+        return context.user.is_authenticated
 
     @classmethod
     def perform_mutation(cls, _root, info, checkout_id):
         checkout = cls.get_node_or_error(
             info, checkout_id, only_type=Checkout, field="checkout_id"
         )
+
+        # Raise error if the current user doesn't own the checkout of the given ID.
+        if checkout.user and checkout.user != info.context.user:
+            raise PermissionDenied()
+
         checkout.user = None
         checkout.save(update_fields=["user", "last_change"])
         return CheckoutCustomerDetach(checkout=checkout)
```
