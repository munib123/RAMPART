# CrossVul Fix Pair: Server-Side Request Forgery (SSRF) in go
**Pair ID:** 1924_0
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**CWE:** CWE-918
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1924_0`)

## Vulnerability Information & PoC

## Description
Server-Side Request Forgery (SSRF) - By providing URLs to unexpected hosts or ports, attackers can make it appear that the server is sending the request, possibly bypassing access controls such as firewalls that prevent the attackers ...

## Vulnerable Code
```go
Lines 2108-2148 of the vulnerable file.

			}
		case *googleapi.Error:
			apiErr = APIError{
				Code:           "XGCSInternalError",
				Description:    e.Message,
				HTTPStatusCode: e.Code,
			}
			// GCS may send multiple errors, just pick the first one
			// since S3 only sends one Error XML response.
			if len(e.Errors) >= 1 {
				apiErr.Code = e.Errors[0].Reason

			}
		case azblob.StorageError:
			apiErr = APIError{
				Code:           string(e.ServiceCode()),
				Description:    e.Error(),
				HTTPStatusCode: e.Response().StatusCode,
			}
			// Add more Gateway SDKs here if any in future.
		}
	}

	return apiErr
}

// getAPIError provides API Error for input API error code.
func getAPIError(code APIErrorCode) APIError {
	if apiErr, ok := errorCodes[code]; ok {
		return apiErr
	}
	return errorCodes.ToAPIErr(ErrInternalError)
}

// getErrorResponse gets in standard error and resource value and
// provides a encodable populated response values
func getAPIErrorResponse(ctx context.Context, err APIError, resource, requestID, hostID string) APIErrorResponse {
	reqInfo := logger.GetReqInfo(ctx)
	return APIErrorResponse{
		Code:       err.Code,
		Message:    err.Description,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2125,6 +2125,12 @@
 				HTTPStatusCode: e.Response().StatusCode,
 			}
 			// Add more Gateway SDKs here if any in future.
+		default:
+			apiErr = APIError{
+				Code:           apiErr.Code,
+				Description:    fmt.Sprintf("%s: cause(%v)", apiErr.Description, err),
+				HTTPStatusCode: apiErr.HTTPStatusCode,
+			}
 		}
 	}
 
```
