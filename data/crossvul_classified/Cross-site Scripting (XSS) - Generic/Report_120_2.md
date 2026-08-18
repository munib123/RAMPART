# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in go
**Pair ID:** 120_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `120_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```go
Lines 231-271 of the vulnerable file.

		k8sEndpoint = &url.URL{Scheme: "https", Host: host + ":" + port}

		var err error
		k8sCertPEM, err = ioutil.ReadFile(k8sInClusterCA)
		if err != nil {
			log.Fatalf("Error inferring Kubernetes config from environment: %v", err)
		}
		rootCAs := x509.NewCertPool()
		if !rootCAs.AppendCertsFromPEM(k8sCertPEM) {
			log.Fatalf("No CA found for the API server")
		}
		tlsConfig := &tls.Config{RootCAs: rootCAs}

		bearerToken, err := ioutil.ReadFile(k8sInClusterBearerToken)
		if err != nil {
			log.Fatalf("failed to read bearer token: %v", err)
		}

		srv.K8sProxyConfig = &proxy.Config{
			TLSClientConfig: tlsConfig,
			HeaderBlacklist: []string{"Cookie"},
			Endpoint:        k8sEndpoint,
		}

		k8sAuthServiceAccountBearerToken = string(bearerToken)

		// If running in an OpenShift cluster, set up a proxy to the prometheus-k8s serivce running in the openshift-monitoring namespace.
		if _, err := os.Stat(openshiftInClusterServiceCA); err == nil {
			serviceCertPEM, err := ioutil.ReadFile(openshiftInClusterServiceCA)
			if err != nil {
				log.Fatalf("failed to read service-ca.crt file: %v", err)
			}
			prometheusProxyRootCAs := x509.NewCertPool()
			if !prometheusProxyRootCAs.AppendCertsFromPEM(serviceCertPEM) {
				log.Fatalf("no CA found for Kubernetes services")
			}
			prometheusTLSConfig := &tls.Config{RootCAs: prometheusProxyRootCAs}
			// Only proxy requests to the Prometheus API, not the UI.
			srv.PrometheusProxyConfig = &proxy.Config{
				TLSClientConfig: prometheusTLSConfig,
				HeaderBlacklist: []string{"Cookie"},
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -248,7 +248,7 @@
 
 		srv.K8sProxyConfig = &proxy.Config{
 			TLSClientConfig: tlsConfig,
-			HeaderBlacklist: []string{"Cookie"},
+			HeaderBlacklist: []string{"Cookie", "X-CSRFToken"},
 			Endpoint:        k8sEndpoint,
 		}
 
@@ -268,7 +268,7 @@
 			// Only proxy requests to the Prometheus API, not the UI.
 			srv.PrometheusProxyConfig = &proxy.Config{
 				TLSClientConfig: prometheusTLSConfig,
-				HeaderBlacklist: []string{"Cookie"},
+				HeaderBlacklist: []string{"Cookie", "X-CSRFToken"},
 				Endpoint:        &url.URL{Scheme: "https", Host: openshiftPrometheusHost, Path: "/api"},
 			}
 		} else if !os.IsNotExist(err) {
@@ -283,7 +283,7 @@
 			TLSClientConfig: &tls.Config{
 				InsecureSkipVerify: *fK8sModeOffClusterSkipVerifyTLS,
 			},
-			HeaderBlacklist: []string{"Cookie"},
+			HeaderBlacklist: []string{"Cookie", "X-CSRFToken"},
 			Endpoint:        k8sEndpoint,
 		}
 	default:
```
