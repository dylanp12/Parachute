package broker

import "net/http"

// authHeaders are headers that may carry credentials from agents.
var authHeaders = []string{
	"Authorization",
	"X-Auth-Token",
	"Private-Token",
}

// StripAndInject removes agent-supplied auth headers and injects the broker credential.
func StripAndInject(req *http.Request, cred *Credential) {
	if cred == nil {
		return
	}
	for _, h := range authHeaders {
		req.Header.Del(h)
	}
	req.Header.Set(cred.HeaderName, cred.HeaderValue)
}

// StripAuth removes auth headers from a request without injecting a replacement.
// Used when the broker denies or credential is unavailable with fail-closed behavior.
func StripAuth(req *http.Request) {
	for _, h := range authHeaders {
		req.Header.Del(h)
	}
}
