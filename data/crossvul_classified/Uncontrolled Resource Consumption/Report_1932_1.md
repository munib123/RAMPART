# CrossVul Fix Pair: Uncontrolled Resource Consumption in go
**Pair ID:** 1932_1
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1932_1`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```go
Lines 146-189 of the vulnerable file.

		conn.WriteJSONError("error saving campaign state")
		return
	}

	// Setting the status to completed stops the query from being sent to
	// targets. If this fails, there is a background job that will clean up
	// this campaign.
	defer func() {
		campaign.Status = kolide.QueryComplete
		_ = svc.ds.SaveDistributedQueryCampaign(campaign)
		_ = svc.liveQueryStore.StopQuery(strconv.Itoa(int(campaign.ID)))
	}()

	status := campaignStatus{
		Status: campaignStatusPending,
	}
	lastStatus := status
	lastTotals := targetTotals{}

	// to improve performance of the frontend rendering the results table, we
	// add the "host_hostname" field to every row.
	mapHostnameRows := func(hostname string, rows []map[string]string) {
		for _, row := range rows {
			row["host_hostname"] = hostname
		}
	}

	hostIDs, labelIDs, err := svc.ds.DistributedQueryCampaignTargetIDs(campaign.ID)
	if err != nil {
		conn.WriteJSONError("error retrieving campaign targets: " + err.Error())
		return
	}

	updateStatus := func() error {
		metrics, err := svc.CountHostsInTargets(context.Background(), hostIDs, labelIDs)
		if err != nil {
			if err = conn.WriteJSONError("error retrieving target counts"); err != nil {
				return errors.New("retrieve target counts")
			}
		}

		totals := targetTotals{
			Total:           metrics.TotalHosts,
			Online:          metrics.OnlineHosts,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -163,11 +163,18 @@
 	lastTotals := targetTotals{}
 
 	// to improve performance of the frontend rendering the results table, we
-	// add the "host_hostname" field to every row.
-	mapHostnameRows := func(hostname string, rows []map[string]string) {
-		for _, row := range rows {
-			row["host_hostname"] = hostname
-		}
+	// add the "host_hostname" field to every row and clean null rows.
+	mapHostnameRows := func(res *kolide.DistributedQueryResult) {
+		filteredRows := []map[string]string{}
+		for _, row := range res.Rows {
+			if row == nil {
+				continue
+			}
+			row["host_hostname"] = res.Host.HostName
+			filteredRows = append(filteredRows, row)
+		}
+
+		res.Rows = filteredRows
 	}
 
 	hostIDs, labelIDs, err := svc.ds.DistributedQueryCampaignTargetIDs(campaign.ID)
@@ -230,7 +237,7 @@
 			// Receive a result and push it over the websocket
 			switch res := res.(type) {
 			case kolide.DistributedQueryResult:
-				mapHostnameRows(res.Host.HostName, res.Rows)
+				mapHostnameRows(&res)
 				err = conn.WriteJSONMessage("result", res)
 				if errors.Cause(err) == sockjs.ErrSessionNotOpen {
 					// return and stop sending the query if the session was closed
```
