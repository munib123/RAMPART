# CrossVul Fix Pair: Uncontrolled Resource Consumption in go
**Pair ID:** 1932_0
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1932_0`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```go
Lines 1-28 of the vulnerable file.

package service

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/go-kit/kit/endpoint"
	kitlog "github.com/go-kit/kit/log"
	"github.com/igm/sockjs-go/v3/sockjs"
	"github.com/fleetdm/fleet/server/contexts/viewer"
	"github.com/fleetdm/fleet/server/kolide"
	"github.com/fleetdm/fleet/server/websocket"
)

////////////////////////////////////////////////////////////////////////////////
// Create Distributed Query Campaign
////////////////////////////////////////////////////////////////////////////////

type createDistributedQueryCampaignRequest struct {
	Query    string                          `json:"query"`
	Selected distributedQueryCampaignTargets `json:"selected"`
}

type distributedQueryCampaignTargets struct {
	Labels []uint `json:"labels"`
	Hosts  []uint `json:"hosts"`
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -5,12 +5,12 @@
 	"encoding/json"
 	"net/http"
 
+	"github.com/fleetdm/fleet/server/contexts/viewer"
+	"github.com/fleetdm/fleet/server/kolide"
+	"github.com/fleetdm/fleet/server/websocket"
 	"github.com/go-kit/kit/endpoint"
 	kitlog "github.com/go-kit/kit/log"
 	"github.com/igm/sockjs-go/v3/sockjs"
-	"github.com/fleetdm/fleet/server/contexts/viewer"
-	"github.com/fleetdm/fleet/server/kolide"
-	"github.com/fleetdm/fleet/server/websocket"
 )
 
 ////////////////////////////////////////////////////////////////////////////////
@@ -79,9 +79,14 @@
 	opt.Websocket = true
 	opt.RawWebsocket = true
 	return sockjs.NewHandler("/api/v1/kolide/results", opt, func(session sockjs.Session) {
-		defer session.Close(0, "none")
-
 		conn := &websocket.Conn{Session: session}
+		defer func() {
+			if p := recover(); p != nil {
+				logger.Log("err", p, "msg", "panic in result handler")
+				conn.WriteJSONError("panic in result handler")
+			}
+			session.Close(0, "none")
+		}()
 
 		// Receive the auth bearer token
 		token, err := conn.ReadAuthToken()
```
