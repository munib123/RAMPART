# CrossVul Fix Pair: Improper Input Validation in go
**Pair ID:** 4443_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4443_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```go
Lines 1-40 of the vulnerable file.

package stats

import (
	"context"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/brocaar/chirpstack-api/go/v3/as"
	"github.com/brocaar/chirpstack-api/go/v3/common"
	"github.com/brocaar/chirpstack-api/go/v3/gw"
	"github.com/brocaar/chirpstack-network-server/internal/backend/gateway"
	"github.com/brocaar/chirpstack-network-server/internal/band"
	"github.com/brocaar/chirpstack-network-server/internal/helpers"
	"github.com/brocaar/chirpstack-network-server/internal/logging"
	"github.com/brocaar/chirpstack-network-server/internal/storage"
	loraband "github.com/brocaar/lorawan/band"
)

type statsContext struct {
	ctx          context.Context
	gateway      storage.Gateway
	gatewayStats gw.GatewayStats
}

var tasks = []func(*statsContext) error{
	getGateway,
	updateGatewayState,
	handleGatewayConfigurationUpdate,
	forwardGatewayStats,
}

// Handle handles the gateway stats
func Handle(ctx context.Context, stats gw.GatewayStats) error {
	sctx := statsContext{
		ctx:          ctx,
		gatewayStats: stats,
	}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -18,6 +18,8 @@
 	loraband "github.com/brocaar/lorawan/band"
 )
 
+var ErrAbort = errors.New("abort")
+
 type statsContext struct {
 	ctx          context.Context
 	gateway      storage.Gateway
@@ -40,6 +42,9 @@
 
 	for _, t := range tasks {
 		if err := t(&sctx); err != nil {
+			if err == ErrAbort {
+				return nil
+			}
 			return err
 		}
 	}
@@ -51,7 +56,15 @@
 	gatewayID := helpers.GetGatewayID(&ctx.gatewayStats)
 	gw, err := storage.GetAndCacheGateway(ctx.ctx, storage.DB(), gatewayID)
 	if err != nil {
-		return errors.Wrap(err, "get gateway error")
+		if errors.Cause(err) == storage.ErrDoesNotExist {
+			log.WithFields(log.Fields{
+				"ctx_id":     ctx.ctx.Value(logging.ContextIDKey),
+				"gateway_id": gatewayID,
+			}).Warning("gateway/stats: stats received by unknown gateway")
+			return ErrAbort
+		} else {
+			return errors.Wrap(err, "get gateway error")
+		}
 	}
 
 	ctx.gateway = gw
```
