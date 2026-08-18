# CrossVul Fix Pair: Insufficiently Protected Credentials in python
**Pair ID:** 765_6
**Vulnerability Class:** Insufficiently Protected Credentials
**CWE:** CWE-522
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `765_6`)

## Vulnerability Information & PoC

## Description
Insufficiently Protected Credentials - The product transmits or stores authentication credentials, but it uses an insecure method that is susceptible to unauthorized interception and/or retrieval.

## Vulnerable Code
```python
Lines 37-77 of the vulnerable file.

    serializer_class = serializers.LoginCodeSerializer
    token_serializer_class = serializers.TokenSerializer
    token_model = Token

    def process_login(self):
        django_login(self.request, self.user)

    def login(self):
        self.user = self.serializer.validated_data['user']
        self.token, created = self.token_model.objects.get_or_create(user=self.user)

        if getattr(settings, 'REST_SESSION_LOGIN', True):
            self.process_login()

    def get_response(self):
        token_serializer = self.token_serializer_class(
            instance=self.token,
            context=self.get_serializer_context(),
        )
        data = token_serializer.data
        data['next'] = self.serializer.validated_data['code'].next
        return Response(data, status=status.HTTP_200_OK)

    def post(self, request, *args, **kwargs):
        self.serializer = self.get_serializer(data=request.data)
        self.serializer.is_valid(raise_exception=True)
        self.serializer.save()
        self.login()
        return self.get_response()


class LogoutView(APIView):
    permission_classes = (AllowAny,)

    def post(self, request, *args, **kwargs):
        return self.logout(request)

    def logout(self, request):
        try:
            request.user.auth_token.delete()
        except (AttributeError, ObjectDoesNotExist):
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -54,7 +54,7 @@
             context=self.get_serializer_context(),
         )
         data = token_serializer.data
-        data['next'] = self.serializer.validated_data['code'].next
+        data['next'] = self.serializer.validated_data['user'].login_code.next
         return Response(data, status=status.HTTP_200_OK)
 
     def post(self, request, *args, **kwargs):
```
