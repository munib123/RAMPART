# CrossVul Fix Pair: Improper Authentication in python
**Pair ID:** 2505_4
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2505_4`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```python
Lines 65-105 of the vulnerable file.

                               domain=domain,
                               salt='zerver.views.auth')
    return response

@require_post
def accounts_register(request):
    # type: (HttpRequest) -> HttpResponse
    key = request.POST['key']
    confirmation = Confirmation.objects.get(confirmation_key=key)
    prereg_user = confirmation.content_object
    email = prereg_user.email
    realm_creation = prereg_user.realm_creation
    password_required = prereg_user.password_required

    validators.validate_email(email)
    if realm_creation:
        # For creating a new realm, there is no existing realm or domain
        realm = None
    else:
        realm = get_realm(get_subdomain(request))
        if prereg_user.realm is not None and prereg_user.realm != realm:
            return render(request, 'confirmation/link_does_not_exist.html')

    if realm and not email_allowed_for_realm(email, realm):
        return render(request, "zerver/closed_realm.html",
                      context={"closed_domain_name": realm.name})

    if realm and realm.deactivated:
        # The user is trying to register for a deactivated realm. Advise them to
        # contact support.
        return redirect_to_deactivation_notice()

    try:
        validate_email_for_realm(realm, email)
    except ValidationError:
        return HttpResponseRedirect(reverse('django.contrib.auth.views.login') + '?email=' +
                                    urllib.parse.quote_plus(email))

    name_validated = False
    full_name = None

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -82,7 +82,9 @@
         realm = None
     else:
         realm = get_realm(get_subdomain(request))
-        if prereg_user.realm is not None and prereg_user.realm != realm:
+        if prereg_user.realm is None:
+            return render(request, 'confirmation/link_expired.html')
+        if prereg_user.realm != realm:
             return render(request, 'confirmation/link_does_not_exist.html')
 
     if realm and not email_allowed_for_realm(email, realm):
```
