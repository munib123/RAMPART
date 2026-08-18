# CrossVul Fix Pair: Improper Input Validation in python
**Pair ID:** 50_6
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `50_6`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```python
Lines 147-187 of the vulnerable file.

@register_blueprint.after_request
@recover_blueprint.after_request
@jwtauth.after_request
@postrequest(sign_response, request=request)
def after_request(response):
    """
    This function is called after a request
    :return: The response
    """
    # In certain error cases the before_request was not handled
    # completely so that we do not have an audit_object
    if "audit_object" in g:
        g.audit_object.finalize_log()

    # No caching!
    response.headers['Cache-Control'] = 'no-cache'
    return response


@validate_blueprint.route('/offlinerefill', methods=['POST'])
@event("validate_offlinerefill", request, g)
def offlinerefill():
    """
    This endpoint allows to fetch new offline OTP values for a token,
    that is already offline.
    According to the definition it will send the missing OTP values, so that
    the client will have as much otp values as defined.

    :param serial: The serial number of the token, that should be refilled.
    :param refilltoken: The authorization token, that allows refilling.
    :param pass: the last password (maybe password+OTP) entered by the user
    :return:
    """
    result = False
    otps = {}
    serial = getParam(request.all_data, "serial", required)
    refilltoken = getParam(request.all_data, "refilltoken", required)
    password = getParam(request.all_data, "pass", required)
    tokenobj_list = get_tokens(serial=serial)
    if len(tokenobj_list) != 1:
        raise ParameterError("The token does not exist")
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -164,6 +164,7 @@
 
 
 @validate_blueprint.route('/offlinerefill', methods=['POST'])
+@check_user_or_serial_in_request(request)
 @event("validate_offlinerefill", request, g)
 def offlinerefill():
     """
```
