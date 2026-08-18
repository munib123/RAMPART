# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in go
**Pair ID:** 3957_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3957_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```go
Lines 10-50 of the vulnerable file.

	sessionmgr "github.com/argoproj/argo-cd/util/session"
)

// Server provides a Session service
type Server struct {
	mgr           *sessionmgr.SessionManager
	authenticator Authenticator
}

type Authenticator interface {
	Authenticate(ctx context.Context) (context.Context, error)
}

// NewServer returns a new instance of the Session service
func NewServer(mgr *sessionmgr.SessionManager, authenticator Authenticator) *Server {
	return &Server{mgr, authenticator}
}

// Create generates a JWT token signed by Argo CD intended for web/CLI logins of the admin user
// using username/password
func (s *Server) Create(ctx context.Context, q *session.SessionCreateRequest) (*session.SessionResponse, error) {
	if q.Token != "" {
		return nil, status.Errorf(codes.Unauthenticated, "token-based session creation no longer supported. please upgrade argocd cli to v0.7+")
	}
	if q.Username == "" || q.Password == "" {
		return nil, status.Errorf(codes.Unauthenticated, "no credentials supplied")
	}
	err := s.mgr.VerifyUsernamePassword(q.Username, q.Password)
	if err != nil {
		return nil, err
	}
	jwtToken, err := s.mgr.Create(q.Username, 0, "")
	if err != nil {
		return nil, err
	}
	return &session.SessionResponse{Token: jwtToken}, nil
}

// Delete an authentication cookie from the client.  This makes sense only for the Web client.
func (s *Server) Delete(ctx context.Context, q *session.SessionDeleteRequest) (*session.SessionResponse, error) {
	return &session.SessionResponse{Token: ""}, nil
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -27,7 +27,7 @@
 
 // Create generates a JWT token signed by Argo CD intended for web/CLI logins of the admin user
 // using username/password
-func (s *Server) Create(ctx context.Context, q *session.SessionCreateRequest) (*session.SessionResponse, error) {
+func (s *Server) Create(_ context.Context, q *session.SessionCreateRequest) (*session.SessionResponse, error) {
 	if q.Token != "" {
 		return nil, status.Errorf(codes.Unauthenticated, "token-based session creation no longer supported. please upgrade argocd cli to v0.7+")
 	}
```
