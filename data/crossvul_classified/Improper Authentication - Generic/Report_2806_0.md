# CrossVul Fix Pair: Improper Authentication in go
**Pair ID:** 2806_0
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2806_0`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```go
Lines 1-30 of the vulnerable file.

// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ldap

import (
	"errors"

	"gopkg.in/asn1-ber.v1"
)

// SimpleBindRequest represents a username/password bind operation
type SimpleBindRequest struct {
	// Username is the name of the Directory object that the client wishes to bind as
	Username string
	// Password is the credentials to bind with
	Password string
	// Controls are optional controls to send with the bind request
	Controls []Control
}

// SimpleBindResult contains the response from the server
type SimpleBindResult struct {
	Controls []Control
}

// NewSimpleBindRequest returns a bind request
func NewSimpleBindRequest(username string, password string, controls []Control) *SimpleBindRequest {
	return &SimpleBindRequest{
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -7,7 +7,7 @@
 import (
 	"errors"
 
-	"gopkg.in/asn1-ber.v1"
+	ber "gopkg.in/asn1-ber.v1"
 )
 
 // SimpleBindRequest represents a username/password bind operation
@@ -18,6 +18,9 @@
 	Password string
 	// Controls are optional controls to send with the bind request
 	Controls []Control
+	// AllowEmptyPassword sets whether the client allows binding with an empty password
+	// (normally used for unauthenticated bind).
+	AllowEmptyPassword bool
 }
 
 // SimpleBindResult contains the response from the server
@@ -28,9 +31,10 @@
 // NewSimpleBindRequest returns a bind request
 func NewSimpleBindRequest(username string, password string, controls []Control) *SimpleBindRequest {
 	return &SimpleBindRequest{
-		Username: username,
-		Password: password,
-		Controls: controls,
+		Username:           username,
+		Password:           password,
+		Controls:           controls,
+		AllowEmptyPassword: false,
 	}
 }
 
@@ -47,6 +51,10 @@
 
 // SimpleBind performs the simple bind operation defined in the given request
 func (l *Conn) SimpleBind(simpleBindRequest *SimpleBindRequest) (*SimpleBindResult, error) {
+	if simpleBindRequest.Password == "" && !simpleBindRequest.AllowEmptyPassword {
+		return nil, NewError(ErrorEmptyPassword, errors.New("ldap: empty password not allowed by the client"))
+	}
+
 	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
 	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, l.nextMessageID(), "MessageID"))
 	encodedBindRequest := simpleBindRequest.encode()
@@ -97,47 +105,33 @@
 	return result, nil
 }
 
-// Bind performs a bind with the given username and password
+// Bind performs a bind with the given username and password.
+//
+// It does not allow unauthenticated bind (i.e. empty password). Use the UnauthenticatedBind method
+// for that.
 func (l *Conn) Bind(username, password string) error {
-	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
-	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, l.nextMessageID(), "MessageID"))
-	bindRequest := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationBindRequest, nil, "Bind Request")
-	bindRequest.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 3, "Version"))
-	bindRequest.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, username, "User Name"))
-	bindRequest.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0, password, "Password"))
-	packet.AppendChild(bindRequest)
+	req := &SimpleBindRequest{
+		Username:           username,
+		Password:           password,
+		AllowEmptyPassword: false,
+	}
+	_, err := l.SimpleBind(req)
+	return err
+}
 
-	if l.Debug {
-		ber.PrintPacket(packet)
+// UnauthenticatedBind performs an unauthenticated bind.
+//
+// A username may be provided for trace (e.g. logging) purpose only, but it is normally not
+// authenticated or otherwise validated by the LDAP server.
+//
+// See https://tools.ietf.org/html/rfc4513#section-5.1.2 .
+// See https://tools.ietf.org/html/rfc4513#section-6.3.1 .
+func (l *Conn) UnauthenticatedBind(username string) error {
+	req := &SimpleBindRequest{
+		Username:           username,
+		Password:           "",
+		AllowEmptyPassword: true,
 	}
-
-	msgCtx, err := l.sendMessage(packet)
-	if err != nil {
-		return err
-	}
-	defer l.finishMessage(msgCtx)
-
-	packetResponse, ok := <-msgCtx.responses
-	if !ok {
-		return NewError(ErrorNetwork, errors.New("ldap: response channel closed"))
-	}
-	packet, err = packetResponse.ReadPacket()
-	l.Debug.Printf("%d: got response %p", msgCtx.id, packet)
-	if err != nil {
-		return err
-	}
-
-	if l.Debug {
-		if err := addLDAPDescriptions(packet); err != nil {
-			return err
-		}
-		ber.PrintPacket(packet)
-	}
-
-	resultCode, resultDescription := getLDAPResultCode(packet)
-	if resultCode != 0 {
-		return NewError(resultCode, errors.New(resultDescription))
-	}
-
-	return nil
+	_, err := l.SimpleBind(req)
+	return err
 }
```
