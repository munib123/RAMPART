# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in python
**Pair ID:** 3112_1
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3112_1`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```python
Lines 555-595 of the vulnerable file.

    '''
    Password reset handling.
    '''
    if 'email' not in load_backends(BACKENDS).keys():
        messages.error(
            request,
            _('Can not reset password, email authentication is disabled!')
        )
        return redirect('login')

    if request.method == 'POST':
        form = ResetForm(request.POST)
        if form.is_valid():
            # Force creating new session
            request.session.create()
            if request.user.is_authenticated():
                logout(request)

            request.session['password_reset'] = True
            return complete(request, 'email')
    else:
        form = ResetForm()

    return render(
        request,
        'accounts/reset.html',
        {
            'title': _('Password reset'),
            'form': form,
        }
    )


@login_required
def reset_api_key(request):
    """Resets user API key"""
    request.user.auth_token.delete()
    Token.objects.create(
        user=request.user,
        key=get_random_string(40)
    )
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -572,6 +572,8 @@
 
             request.session['password_reset'] = True
             return complete(request, 'email')
+        else:
+            return redirect('email-sent')
     else:
         form = ResetForm()
 
```
