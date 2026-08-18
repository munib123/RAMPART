# CrossVul Fix Pair: Cleartext Storage of Sensitive Information in typescript
**Pair ID:** 4082_1
**Vulnerability Class:** Cleartext Storage of Sensitive Information
**CWE:** CWE-312
**Language:** typescript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4082_1`)

## Vulnerability Information & PoC

## Description
Cleartext Storage of Sensitive Information - Because the information is stored in cleartext (i.

## Vulnerable Code
```typescript
Lines 1-31 of the vulnerable file.

import {
  ApolloClient,
  ApolloError,
  ObservableQuery,
  WatchQueryOptions,
} from "apollo-client";
import { GraphQLError } from "graphql";

import { fireSignOut, getAuthToken, setAuthToken } from "../auth";
import { MUTATIONS } from "../mutations";
import { TokenAuth } from "../mutations/gqlTypes/TokenAuth";
import { QUERIES } from "../queries";
import { UserDetails } from "../queries/gqlTypes/UserDetails";
import { RequireAtLeastOne } from "../tsHelpers";
import {
  InferOptions,
  MapFn,
  QueryShape,
  WatchMapFn,
  WatchQueryData,
} from "../types";
import {
  getErrorsFromData,
  getMappedData,
  isDataEmpty,
  mergeEdges,
} from "../utils";

export class APIProxy {
  getAttributes = this.watchQuery(QUERIES.Attributes, data => data.attributes);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -8,7 +8,12 @@
 
 import { fireSignOut, getAuthToken, setAuthToken } from "../auth";
 import { MUTATIONS } from "../mutations";
-import { TokenAuth } from "../mutations/gqlTypes/TokenAuth";
+import { PasswordChange } from "../mutations/gqlTypes/PasswordChange";
+import { SetPassword } from "../mutations/gqlTypes/SetPassword";
+import {
+  TokenAuth,
+  TokenAuth_tokenCreatte,
+} from "../mutations/gqlTypes/TokenAuth";
 import { QUERIES } from "../queries";
 import { UserDetails } from "../queries/gqlTypes/UserDetails";
 import { RequireAtLeastOne } from "../tsHelpers";
@@ -25,66 +30,69 @@
   isDataEmpty,
   mergeEdges,
 } from "../utils";
+import { SetPasswordChange, SetPasswordResult, SignIn } from "./types";
 
 export class APIProxy {
-  getAttributes = this.watchQuery(QUERIES.Attributes, data => data.attributes);
+  getAttributes = this.watchQuery(
+    QUERIES.Attributes,
+    (data) => data.attributes
+  );
 
   getProductDetails = this.watchQuery(
     QUERIES.ProductDetails,
-    data => data.product
-  );
-
-  getProductList = this.watchQuery(QUERIES.ProductList, data => data.products);
+    (data) => data.product
+  );
+
+  getProductList = this.watchQuery(
+    QUERIES.ProductList,
+    (data) => data.products
+  );
 
   getCategoryDetails = this.watchQuery(
     QUERIES.CategoryDetails,
-    data => data.category
-  );
-
-  getOrdersByUser = this.watchQuery(QUERIES.OrdersByUser, data =>
+    (data) => data.category
+  );
+
+  getOrdersByUser = this.watchQuery(QUERIES.OrdersByUser, (data) =>
     data.me ? data.me.orders : null
   );
 
   getOrderDetails = this.watchQuery(
     QUERIES.OrderDetails,
-    data => data.orderByToken
+    (data) => data.orderByToken
   );
 
   getVariantsProducts = this.watchQuery(
     QUERIES.VariantsProducts,
-    data => data.productVariants
-  );
-
-  getShopDetails = this.watchQuery(QUERIES.GetShopDetails, data => data);
+    (data) => data.productVariants
+  );
+
+  getShopDetails = this.watchQuery(QUERIES.GetShopDetails, (data) => data);
 
   setUserDefaultAddress = this.fireQuery(
     MUTATIONS.AddressTypeUpdate,
-    data => data!.accountSetDefaultAddress
+    (data) => data!.accountSetDefaultAddress
   );
 
   setDeleteUserAddress = this.fireQuery(
     MUTATIONS.DeleteUserAddress,
-    data => data!.accountAddressDelete
+    (data) => data!.accountAddressDelete
   );
 
   setCreateUserAddress = this.fireQuery(
     MUTATIONS.CreateUserAddress,
-    data => data!.accountAddressCreate
+    (data) => data!.accountAddressCreate
   );
 
   setUpdateuserAddress = this.fireQuery(
     MUTATIONS.UpdateUserAddress,
-    data => data!.accountAddressUpdate
+    (data) => data!.accountAddressUpdate
   );
 
   setAccountUpdate = this.fireQuery(
     MUTATIONS.AccountUpdate,
-    data => data!.accountUpdate
-  );
-
-  setPasswordChange = this.fireQuery(MUTATIONS.PasswordChange, data => data);
-
-  setPassword = this.fireQuery(MUTATIONS.SetPassword, data => data);
+    (data) => data!.accountUpdate
+  );
 
   client: ApolloClient<any>;
 
@@ -99,7 +107,7 @@
     }
   ) => {
     if (this.isLoggedIn()) {
-      return this.watchQuery(QUERIES.UserDetails, data => data.me)(
+      return this.watchQuery(QUERIES.UserDetails, (data) => data.me)(
         variables,
         options
       );
@@ -116,47 +124,40 @@
     };
   };
 
-  signIn = (
+  signIn = async (
     variables: InferOptions<MUTATIONS["TokenAuth"]>["variables"],
     options?: Omit<InferOptions<MUTATIONS["TokenAuth"]>, "variables">
-  ) =>
-    new Promise<{ data: TokenAuth["tokenCreate"] }>(async (resolve, reject) => {
-      try {
-        this.client.resetStore();
-
-        const data = await this.fireQuery(
-          MUTATIONS.TokenAuth,
-          data => data!.tokenCreate
-        )(variables, {
-          ...options,
-          update: (proxy, data) => {
-            const handledData = handleDataErrors(
-              (data: any) => data.tokenCreate,
-              data.data,
-              data.errors
-            );
-            if (!handledData.errors && handledData.data) {
-              setAuthToken(handledData.data.token);
-              if (window.PasswordCredential && variables) {
-                navigator.credentials.store(
-                  new window.PasswordCredential({
-                    id: variables.email,
-                    password: variables.password,
-                  })
-                );
-              }
-            }
-            if (options && options.update) {
-              options.update(proxy, data);
-            }
-          },
-        });
-
-        resolve(data);
-      } catch (e) {
-        reject(e);
-      }
+  ): Promise<SignIn> => {
+    await this.client.resetStore();
+    let result: {
+      data: TokenAuth_tokenCreate | null;
+    } | null = null;
+
+    result = await this.fireQuery(
+      MUTATIONS.TokenAuth,
+      (mutationData) => mutationData!.tokenCreate
+    )(variables, {
+      ...options,
+      fetchPolicy: "no-cache",
     });
+    const { data } = result;
+
+    if (data?.token && data.errors.length === 0) {
+      setAuthToken(data.token);
+      if (window.PasswordCredential && variables) {
+        navigator.credentials.store(
+          new window.PasswordCredential({
+            id: variables.email,
+            password: variables.password,
+          })
+        );
+      }
+    }
+    return {
+      data,
+      error: null,
+    };
+  };
 
   signOut = () =>
     new Promise(async (resolve, reject) => {
@@ -168,6 +169,52 @@
         reject(e);
       }
     });
+
+  setPassword = async (
+    variables: InferOptions<MUTATIONS["SetPassword"]>["variables"],
+    options?: Omit<InferOptions<MUTATIONS["SetPassword"]>, "variables">
+  ): Promise<SetPasswordResult> => {
+    let result: {
+      data: SetPassword | null;
+    } | null = null;
+
+    result = await this.fireQuery(MUTATIONS.SetPassword, (data) => data!)(
+      variables,
+      {
+        ...options,
+        fetchPolicy: "no-cache",
+      }
+    );
+    const { data } = result;
+
+    return {
+      data,
+      error: null,
+    };
+  };
+
+  setPasswordChange = async (
+    variables: InferOptions<MUTATIONS["PasswordChange"]>["variables"],
+    options?: Omit<InferOptions<MUTATIONS["PasswordChange"]>, "variables">
+  ): Promise<SetPasswordChange> => {
+    let result: {
+      data: PasswordChange | null;
+    } | null = null;
+
+    result = await this.fireQuery(MUTATIONS.PasswordChange, (data) => data!)(
+      variables,
+      {
+        ...options,
+        fetchPolicy: "no-cache",
+      }
+    );
+    const { data } = result;
+
+    return {
+      data,
+      error: null,
+    };
+  };
 
   attachAuthListener = (callback: (authenticated: boolean) => void) => {
     const eventHandler = () => {
@@ -226,7 +273,7 @@
       }
 
       const subscription = observable.subscribe(
-        result => {
+        (result) => {
           const { data, errors: apolloErrors } = result;
           const errorHandledData = handleDataErrors(
             mapFn,
@@ -246,7 +293,7 @@
             }
           }
         },
-        error => {
+        (error) => {
           if (onError) {
             onError(error);
           }
@@ -281,7 +328,7 @@
                 );
 
                 // use new result for metadata and mutate existing data
-                Object.keys(prevResultRef).forEach(key => {
+                Object.keys(prevResultRef).forEach((key) => {
                   prevResultRef[key] = newResultRef[key];
                 });
                 prevResultRef.edges = mergedEdges;
```
