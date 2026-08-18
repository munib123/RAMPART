# CrossVul Fix Pair: Cleartext Storage of Sensitive Information in typescript
**Pair ID:** 4082_2
**Vulnerability Class:** Cleartext Storage of Sensitive Information
**CWE:** CWE-312
**Language:** typescript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4082_2`)

## Vulnerability Information & PoC

## Description
Cleartext Storage of Sensitive Information - Because the information is stored in cleartext (i.

## Vulnerable Code
```typescript
Lines 1-17 of the vulnerable file.

export interface ErrorResponse<T> {
  error?: any;
  type?: T;
}

export interface FunctionQueueResponse {
  pending: boolean;
}
export interface FunctionRunResponse<D, F> {
  data?: any;
  dataError?: ErrorResponse<D>;
  functionError?: ErrorResponse<F>;
  pending: boolean;
}

export type PromiseQueuedResponse = Promise<FunctionQueueResponse>;
export type PromiseRunResponse<D, F> = Promise<FunctionRunResponse<D, F>>;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,3 +1,8 @@
+import { ApolloError } from "apollo-client";
+import { PasswordChange } from "../mutations/gqlTypes/PasswordChange";
+import { SetPassword } from "../mutations/gqlTypes/SetPassword";
+import { TokenAuth_tokenCreate } from "../mutations/gqlTypes/TokenAuth";
+
 export interface ErrorResponse<T> {
   error?: any;
   type?: T;
@@ -15,3 +20,18 @@
 
 export type PromiseQueuedResponse = Promise<FunctionQueueResponse>;
 export type PromiseRunResponse<D, F> = Promise<FunctionRunResponse<D, F>>;
+
+export type SignIn = {
+  data: TokenAuth_tokenCreate | null;
+  error: ApolloError | null;
+} | null;
+
+export type SetPasswordChange = {
+  data: PasswordChange | null;
+  error: ApolloError | null;
+} | null;
+
+export type SetPasswordResult = {
+  data: SetPassword | null;
+  error: ApolloError | null;
+} | null;
```
