package auth

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	oidc "github.com/coreos/go-oidc"
	log "github.com/sirupsen/logrus"
	"github.com/zalando/skipper/filters"
	logfilter "github.com/zalando/skipper/filters/log"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/oauth2"
)

type roleCheckType int

const (
	checkOAuthTokeninfoAnyScopes roleCheckType = iota
	checkOAuthTokeninfoAllScopes
	checkOAuthTokeninfoAnyKV
	checkOAuthTokeninfoAllKV
	checkOAuthTokenintrospectionAnyClaims
	checkOAuthTokenintrospectionAllClaims
	checkOAuthTokenintrospectionAnyKV
	checkOAuthTokenintrospectionAllKV
	checkOidcUserInfos
	checkOidcAnyClaims
	checkOidcAllClaims
	checkUnknown
)

type rejectReason string

const (
	missingBearerToken rejectReason = "missing-bearer-token"
	missingToken       rejectReason = "missing-token"
	authServiceAccess  rejectReason = "auth-service-access"
	invalidSub         rejectReason = "invalid-sub-in-token"
	inactiveToken      rejectReason = "inactive-token"
	invalidToken       rejectReason = "invalid-token"
	invalidScope       rejectReason = "invalid-scope"
	invalidClaim       rejectReason = "invalid-claim"
)

const (
	OAuthTokeninfoAnyScopeName           = "oauthTokeninfoAnyScope"
	OAuthTokeninfoAllScopeName           = "oauthTokeninfoAllScope"
	OAuthTokeninfoAnyKVName              = "oauthTokeninfoAnyKV"
	OAuthTokeninfoAllKVName              = "oauthTokeninfoAllKV"
	OAuthTokenintrospectionAnyClaimsName = "oauthTokenintrospectionAnyClaims"
	OAuthTokenintrospectionAllClaimsName = "oauthTokenintrospectionAllClaims"
	OAuthTokenintrospectionAnyKVName     = "oauthTokenintrospectionAnyKV"
	OAuthTokenintrospectionAllKVName     = "oauthTokenintrospectionAllKV"
	OidcUserInfoName                     = "oauthOidcUserInfo"
	OidcAnyClaimsName                    = "oauthOidcAnyClaims"
	OidcAllClaimsName                    = "oauthOidcAllClaims"
	AuthUnknown                          = "authUnknown"

	authHeaderName               = "Authorization"
	authHeaderPrefix             = "Bearer "
	accessTokenQueryKey          = "access_token"
	scopeKey                     = "scope"
	uidKey                       = "uid"
	tokeninfoCacheKey            = "tokeninfo"
	tokenintrospectionCacheKey   = "tokenintrospection"
	tokenIntrospectionConfigPath = "/.well-known/openid-configuration"
	oidcStatebagKey              = "oauthOidcKey"
	oauthOidcCookieName          = "skipperOauthOidc"
)

type (
	authClient struct {
		url *url.URL
	}

	kv map[string]string

	tokeninfoSpec struct {
		typ          roleCheckType
		tokeninfoURL string
		authClient   *authClient
	}

	tokeninfoFilter struct {
		typ        roleCheckType
		authClient *authClient
		scopes     []string
		kv         kv
	}

	tokenIntrospectionSpec struct {
		typ              roleCheckType
		issuerURL        string
		introspectionURL string
		config           *openIDConfig
		authClient       *authClient // TODO(sszuecs): might be different
	}

	openIDConfig struct {
		Issuer                            string   `json:"issuer"`
		AuthorizationEndpoint             string   `json:"authorization_endpoint"`
		TokenEndpoint                     string   `json:"token_endpoint"`
		UserinfoEndpoint                  string   `json:"userinfo_endpoint"`
		RevocationEndpoint                string   `json:"revocation_endpoint"`
		JwksURI                           string   `json:"jwks_uri"`
		RegistrationEndpoint              string   `json:"registration_endpoint"`
		IntrospectionEndpoint             string   `json:"introspection_endpoint"`
		ResponseTypesSupported            []string `json:"response_types_supported"`
		SubjectTypesSupported             []string `json:"subject_types_supported"`
		IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
		TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
		ClaimsSupported                   []string `json:"claims_supported"`
		ScopesSupported                   []string `json:"scopes_supported"`
		CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	}

	tokenIntrospectionInfo map[string]interface{}

	tokenintrospectFilter struct {
		typ        roleCheckType
		authClient *authClient // TODO(sszuecs): might be different
		claims     []string
		kv         kv
	}
)

var (
	errUnsupportedClaimSpecified     = errors.New("unsupported claim specified in filter")
	errInvalidAuthorizationHeader    = errors.New("invalid authorization header")
	errInvalidToken                  = errors.New("invalid token")
	errInvalidTokenintrospectionData = errors.New("invalid tokenintrospection data")
)

func (kv kv) String() string {
	var res []string
	for k, v := range kv {
		res = append(res, k, v)
	}
	return strings.Join(res, ",")
}

func getToken(r *http.Request) (string, error) {
	if tok := r.URL.Query().Get(accessTokenQueryKey); tok != "" {
		return tok, nil
	}

	h := r.Header.Get(authHeaderName)
	if !strings.HasPrefix(h, authHeaderPrefix) {
		return "", errInvalidAuthorizationHeader
	}

	return h[len(authHeaderPrefix):], nil
}

func unauthorized(ctx filters.FilterContext, uname string, reason rejectReason, hostname string) {
	ctx.StateBag()[logfilter.AuthUserKey] = uname
	ctx.StateBag()[logfilter.AuthRejectReasonKey] = string(reason)
	rsp := &http.Response{
		StatusCode: http.StatusUnauthorized,
		Header:     make(map[string][]string),
	}
	// https://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html#sec10.4.2
	rsp.Header.Add("WWW-Authenticate", hostname)
	ctx.Serve(rsp)
}

func authorized(ctx filters.FilterContext, uname string) {
	ctx.StateBag()[logfilter.AuthUserKey] = uname
}

func getStrings(args []interface{}) ([]string, error) {
	s := make([]string, len(args))
	var ok bool
	for i, a := range args {
		s[i], ok = a.(string)
		if !ok {
			return nil, filters.ErrInvalidFilterParameters
		}
	}

	return s, nil
}

// all checks that all strings in the left are also in the
// right. Right can be a superset of left.
func all(left, right []string) bool {
	for _, l := range left {
		var found bool
		for _, r := range right {
			if l == r {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// intersect checks that one string in the left is also in the right
func intersect(left, right []string) bool {
	for _, l := range left {
		for _, r := range right {
			if l == r {
				return true
			}
		}
	}

	return false
}

// jsonGet requests url with access token in the URL query specified
// by accessTokenQueryKey, if auth was given and writes into doc.
func jsonGet(url *url.URL, auth string, doc interface{}) error {
	if auth != "" {
		q := url.Query()
		q.Add(accessTokenQueryKey, auth)
		url.RawQuery = q.Encode()
	}

	req, err := http.NewRequest("GET", url.String(), nil)
	if err != nil {
		return err
	}

	rsp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}

	defer rsp.Body.Close()
	if rsp.StatusCode != 200 {
		return errInvalidToken
	}

	d := json.NewDecoder(rsp.Body)
	return d.Decode(doc)
}

// jsonPost requests url with access token in the body, if auth was given and writes into doc.
func jsonPost(u *url.URL, auth string, doc *tokenIntrospectionInfo) error {
	body := url.Values{}
	body.Add("token", auth)

	rsp, err := http.PostForm(u.String(), body)
	if err != nil {
		return err
	}

	defer rsp.Body.Close()
	if rsp.StatusCode != 200 {
		return errInvalidToken
	}
	buf := make([]byte, rsp.ContentLength)
	n, _ := rsp.Body.Read(buf)
	if int64(n) != rsp.ContentLength {
		log.Infof("content-length missmatch body read %d != %d", rsp.ContentLength, n)
	}
	err = json.Unmarshal(buf, &doc)
	if err != nil {
		log.Infof("Failed to unmarshal data: %v", err)
		return err
	}
	return err
}

func newAuthClient(baseURL string) (*authClient, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	return &authClient{url: u}, nil
}

func (ac *authClient) getTokeninfo(token string) (map[string]interface{}, error) {
	var a map[string]interface{}
	err := jsonGet(ac.url, token, &a)
	return a, err
}

func (ac *authClient) getTokenintrospect(token string) (tokenIntrospectionInfo, error) {
	info := make(tokenIntrospectionInfo)
	err := jsonPost(ac.url, token, &info)
	if err != nil {
		return nil, err
	}
	return info, err
}

// Active returns token introspection response, which is true if token
// is not revoked and in the time frame of
// validity. https://tools.ietf.org/html/rfc7662#section-2.2
func (tii tokenIntrospectionInfo) Active() bool {
	return tii.getBoolValue("active")
}

func (tii tokenIntrospectionInfo) AuthTime() (time.Time, error) {
	return tii.getUNIXTimeValue("auth_time")
}

func (tii tokenIntrospectionInfo) Azp() (string, error) {
	return tii.getStringValue("azp")
}

func (tii tokenIntrospectionInfo) Exp() (time.Time, error) {
	return tii.getUNIXTimeValue("exp")
}

func (tii tokenIntrospectionInfo) Iat() (time.Time, error) {
	return tii.getUNIXTimeValue("iat")
}

func (tii tokenIntrospectionInfo) Issuer() (string, error) {
	return tii.getStringValue("iss")
}

func (tii tokenIntrospectionInfo) Sub() (string, error) {
	return tii.getStringValue("sub")
}

func (tii tokenIntrospectionInfo) getBoolValue(k string) bool {
	if active, ok := tii[k].(bool); ok {
		return active
	}
	return false
}

func (tii tokenIntrospectionInfo) getStringValue(k string) (string, error) {
	s, ok := tii[k].(string)
	if !ok {
		return "", errInvalidTokenintrospectionData
	}
	return s, nil
}

func (tii tokenIntrospectionInfo) getUNIXTimeValue(k string) (time.Time, error) {
	ts, ok := tii[k].(string)
	if !ok {
		return time.Time{}, errInvalidTokenintrospectionData
	}
	ti, err := strconv.Atoi(ts)
	if err != nil {
		return time.Time{}, errInvalidTokenintrospectionData
	}

	return time.Unix(int64(ti), 0), nil
}

// NewOAuthTokeninfoAllScope creates a new auth filter specification
// to validate authorization for requests. Current implementation uses
// Bearer tokens to authorize requests and checks that the token
// contains all scopes.
func NewOAuthTokeninfoAllScope(OAuthTokeninfoURL string) filters.Spec {
	return &tokeninfoSpec{typ: checkOAuthTokeninfoAllScopes, tokeninfoURL: OAuthTokeninfoURL}
}

// NewOAuthTokeninfoAnyScope creates a new auth filter specification
// to validate authorization for requests. Current implementation uses
// Bearer tokens to authorize requests and checks that the token
// contains at least one scope.
func NewOAuthTokeninfoAnyScope(OAuthTokeninfoURL string) filters.Spec {
	return &tokeninfoSpec{typ: checkOAuthTokeninfoAnyScopes, tokeninfoURL: OAuthTokeninfoURL}
}

// NewOAuthTokeninfoAllKV creates a new auth filter specification
// to validate authorization for requests. Current implementation uses
// Bearer tokens to authorize requests and checks that the token
// contains all key value pairs provided.
func NewOAuthTokeninfoAllKV(OAuthTokeninfoURL string) filters.Spec {
	return &tokeninfoSpec{typ: checkOAuthTokeninfoAllKV, tokeninfoURL: OAuthTokeninfoURL}
}

// NewOAuthTokeninfoAnyKV creates a new auth filter specification
// to validate authorization for requests. Current implementation uses
// Bearer tokens to authorize requests and checks that the token
// contains at least one key value pair provided.
func NewOAuthTokeninfoAnyKV(OAuthTokeninfoURL string) filters.Spec {
	return &tokeninfoSpec{typ: checkOAuthTokeninfoAnyKV, tokeninfoURL: OAuthTokeninfoURL}
}

func (s *tokeninfoSpec) Name() string {
	switch s.typ {
	case checkOAuthTokeninfoAnyScopes:
		return OAuthTokeninfoAnyScopeName
	case checkOAuthTokeninfoAllScopes:
		return OAuthTokeninfoAllScopeName
	case checkOAuthTokeninfoAnyKV:
		return OAuthTokeninfoAnyKVName
	case checkOAuthTokeninfoAllKV:
		return OAuthTokeninfoAllKVName
	}
	return AuthUnknown
}

// CreateFilter creates an auth filter. All arguments have to be
// strings. Depending on the variant of the auth tokeninfoFilter, the arguments
// represent scopes or key-value pairs to be checked in the tokeninfo
// response. How scopes or key value pairs are checked is based on the
// type. The shown example for checkOAuthTokeninfoAllScopes will grant
// access only to tokens, that have scopes read-x and write-y:
//
//     s.CreateFilter(read-x", "write-y")
//
func (s *tokeninfoSpec) CreateFilter(args []interface{}) (filters.Filter, error) {
	sargs, err := getStrings(args)
	if err != nil {
		return nil, err
	}
	if len(sargs) == 0 {
		return nil, filters.ErrInvalidFilterParameters
	}

	ac, err := newAuthClient(s.tokeninfoURL)
	if err != nil {
		return nil, filters.ErrInvalidFilterParameters
	}

	f := &tokeninfoFilter{typ: s.typ, authClient: ac, kv: make(map[string]string)}
	switch f.typ {
	// all scopes
	case checkOAuthTokeninfoAllScopes:
		fallthrough
	case checkOAuthTokeninfoAnyScopes:
		f.scopes = sargs[:]
	// key value pairs
	case checkOAuthTokeninfoAnyKV:
		fallthrough
	case checkOAuthTokeninfoAllKV:
		for i := 0; i+1 < len(sargs); i += 2 {
			f.kv[sargs[i]] = sargs[i+1]
		}
		if len(sargs) == 0 || len(sargs)%2 != 0 {
			return nil, filters.ErrInvalidFilterParameters
		}
	default:
		return nil, filters.ErrInvalidFilterParameters
	}

	return f, nil
}

// String prints nicely the tokeninfoFilter configuration based on the
// configuration and check used.
func (f *tokeninfoFilter) String() string {
	switch f.typ {
	case checkOAuthTokeninfoAnyScopes:
		return fmt.Sprintf("%s(%s)", OAuthTokeninfoAnyScopeName, strings.Join(f.scopes, ","))
	case checkOAuthTokeninfoAllScopes:
		return fmt.Sprintf("%s(%s)", OAuthTokeninfoAllScopeName, strings.Join(f.scopes, ","))
	case checkOAuthTokeninfoAnyKV:
		return fmt.Sprintf("%s(%s)", OAuthTokeninfoAnyKVName, f.kv)
	case checkOAuthTokeninfoAllKV:
		return fmt.Sprintf("%s(%s)", OAuthTokeninfoAllKVName, f.kv)
	}
	return AuthUnknown
}

func (f *tokeninfoFilter) validateAnyScopes(h map[string]interface{}) bool {
	if len(f.scopes) == 0 {
		return true
	}

	vI, ok := h[scopeKey]
	if !ok {
		return false
	}
	v, ok := vI.([]interface{})
	if !ok {
		return false
	}
	var a []string
	for i := range v {
		s, ok := v[i].(string)
		if !ok {
			return false
		}
		a = append(a, s)
	}

	return intersect(f.scopes, a)
}

func (f *tokeninfoFilter) validateAllScopes(h map[string]interface{}) bool {
	if len(f.scopes) == 0 {
		return true
	}

	vI, ok := h[scopeKey]
	if !ok {
		return false
	}
	v, ok := vI.([]interface{})
	if !ok {
		return false
	}
	var a []string
	for i := range v {
		s, ok := v[i].(string)
		if !ok {
			return false
		}
		a = append(a, s)
	}

	return all(f.scopes, a)
}

func (f *tokeninfoFilter) validateAnyKV(h map[string]interface{}) bool {
	for k, v := range f.kv {
		if v2, ok := h[k].(string); ok {
			if v == v2 {
				return true
			}
		}
	}
	return false
}

func (f *tokeninfoFilter) validateAllKV(h map[string]interface{}) bool {
	if len(h) < len(f.kv) {
		return false
	}
	for k, v := range f.kv {
		v2, ok := h[k].(string)
		if !ok || v != v2 {
			return false
		}
	}
	return true
}

// Request handles authentication based on the defined auth type.
func (f *tokeninfoFilter) Request(ctx filters.FilterContext) {
	r := ctx.Request()

	var authMap map[string]interface{}
	authMapTemp, ok := ctx.StateBag()[tokeninfoCacheKey]
	if !ok {
		token, err := getToken(r)
		if err != nil {
			unauthorized(ctx, "", missingBearerToken, f.authClient.url.Hostname())
			return
		}
		if token == "" {
			unauthorized(ctx, "", missingBearerToken, f.authClient.url.Hostname())
			return
		}

		authMap, err = f.authClient.getTokeninfo(token)
		if err != nil {
			reason := authServiceAccess
			if err == errInvalidToken {
				reason = invalidToken
			}
			unauthorized(ctx, "", reason, f.authClient.url.Hostname())
			return
		}
	} else {
		authMap = authMapTemp.(map[string]interface{})
	}

	uid, _ := authMap[uidKey].(string) // uid can be empty string, but if not we set the who for auditlogging

	var allowed bool
	switch f.typ {
	case checkOAuthTokeninfoAnyScopes:
		allowed = f.validateAnyScopes(authMap)
	case checkOAuthTokeninfoAllScopes:
		allowed = f.validateAllScopes(authMap)
	case checkOAuthTokeninfoAnyKV:
		allowed = f.validateAnyKV(authMap)
	case checkOAuthTokeninfoAllKV:
		allowed = f.validateAllKV(authMap)
	default:
		log.Errorf("Wrong tokeninfoFilter type: %s", f)
	}

	if !allowed {
		unauthorized(ctx, uid, invalidScope, f.authClient.url.Hostname())
	} else {
		authorized(ctx, uid)
	}
	ctx.StateBag()[tokeninfoCacheKey] = authMap
}

func (f *tokeninfoFilter) Response(filters.FilterContext) {}

// NewOAuthTokenintrospectionAnyKV creates a new auth filter specification
// to validate authorization for requests. Current implementation uses
// Bearer tokens to authorize requests and checks that the token
// contains at least one key value pair provided.
//
// This is implementing RFC 7662 compliant implementation. It uses
// POST requests to call introspection_endpoint to get the information
// of the token validity.
//
// It uses /.well-known/openid-configuration path to the passed
// oauthIssuerURL to find introspection_endpoint as defined in draft
// https://tools.ietf.org/html/draft-ietf-oauth-discovery-06, if
// oauthIntrospectionURL is a non empty string, it will set
// IntrospectionEndpoint to the given oauthIntrospectionURL.
func NewOAuthTokenintrospectionAnyKV(oauthIssuerURL, oauthIntrospectionURL string) filters.Spec {
	return newOAuthTokenintrospectionFilter(checkOAuthTokenintrospectionAnyKV, oauthIssuerURL, oauthIntrospectionURL)
}

// NewOAuthTokenintrospectionAllKV creates a new auth filter specification
// to validate authorization for requests. Current implementation uses
// Bearer tokens to authorize requests and checks that the token
// contains at least one key value pair provided.
//
// This is implementing RFC 7662 compliant implementation. It uses
// POST requests to call introspection_endpoint to get the information
// of the token validity.
//
// It uses /.well-known/openid-configuration path to the passed
// oauthIssuerURL to find introspection_endpoint as defined in draft
// https://tools.ietf.org/html/draft-ietf-oauth-discovery-06, if
// oauthIntrospectionURL is a non empty string, it will set
// IntrospectionEndpoint to the given oauthIntrospectionURL.
func NewOAuthTokenintrospectionAllKV(oauthIssuerURL, oauthIntrospectionURL string) filters.Spec {
	return newOAuthTokenintrospectionFilter(checkOAuthTokenintrospectionAllKV, oauthIssuerURL, oauthIntrospectionURL)
}

func NewOAuthTokenintrospectionAnyClaims(oauthIssuerURL, oauthIntrospectionURL string) filters.Spec {
	return newOAuthTokenintrospectionFilter(checkOAuthTokenintrospectionAnyClaims, oauthIssuerURL, oauthIntrospectionURL)
}

func NewOAuthTokenintrospectionAllClaims(oauthIssuerURL, oauthIntrospectionURL string) filters.Spec {
	return newOAuthTokenintrospectionFilter(checkOAuthTokenintrospectionAllClaims, oauthIssuerURL, oauthIntrospectionURL)
}

func newOAuthTokenintrospectionFilter(typ roleCheckType, oauthIssuerURL, oauthIntrospectionURL string) filters.Spec {
	cfg, err := getOpenIDConfig(oauthIssuerURL)
	if err != nil {
		return &tokenIntrospectionSpec{
			typ:              typ,
			issuerURL:        oauthIssuerURL,
			introspectionURL: oauthIntrospectionURL,
		}
	}

	if oauthIntrospectionURL != "" {
		cfg.IntrospectionEndpoint = oauthIntrospectionURL
	}
	return &tokenIntrospectionSpec{
		typ:              typ,
		issuerURL:        oauthIssuerURL,
		introspectionURL: cfg.IntrospectionEndpoint,
		config:           cfg,
	}
}

func getOpenIDConfig(issuerURL string) (*openIDConfig, error) {
	u, err := url.Parse(issuerURL + tokenIntrospectionConfigPath)
	if err != nil {
		return nil, err
	}

	var cfg openIDConfig
	err = jsonGet(u, "", &cfg)
	return &cfg, err
}

func (s *tokenIntrospectionSpec) Name() string {
	switch s.typ {
	case checkOAuthTokenintrospectionAnyClaims:
		return OAuthTokenintrospectionAnyClaimsName
	case checkOAuthTokenintrospectionAllClaims:
		return OAuthTokenintrospectionAllClaimsName
	case checkOAuthTokenintrospectionAnyKV:
		return OAuthTokenintrospectionAnyKVName
	case checkOAuthTokenintrospectionAllKV:
		return OAuthTokenintrospectionAllKVName
	}
	return AuthUnknown
}

func (s *tokenIntrospectionSpec) CreateFilter(args []interface{}) (filters.Filter, error) {
	sargs, err := getStrings(args)
	if err != nil {
		return nil, err
	}
	if len(sargs) == 0 || s.introspectionURL == "" {
		return nil, filters.ErrInvalidFilterParameters
	}

	ac, err := newAuthClient(s.introspectionURL)
	if err != nil {
		return nil, filters.ErrInvalidFilterParameters
	}

	f := &tokenintrospectFilter{
		typ:        s.typ,
		authClient: ac,
		kv:         make(map[string]string),
	}
	switch f.typ {
	// similar to key value pairs but additionally checks claims to be supported before creating the filter
	case checkOAuthTokenintrospectionAllClaims:
		fallthrough
	case checkOAuthTokenintrospectionAnyClaims:
		f.claims = sargs[:]
		if s.config != nil && !all(f.claims, s.config.ClaimsSupported) {
			return nil, errUnsupportedClaimSpecified
		}
		fallthrough
	// key value pairs
	case checkOAuthTokenintrospectionAllKV:
		fallthrough
	case checkOAuthTokenintrospectionAnyKV:
		for i := 0; i+1 < len(sargs); i += 2 {
			f.kv[sargs[i]] = sargs[i+1]
		}
		if len(sargs) == 0 || len(sargs)%2 != 0 {
			return nil, filters.ErrInvalidFilterParameters
		}
	default:
		return nil, filters.ErrInvalidFilterParameters
	}

	return f, nil
}

// String prints nicely the tokenintrospectFilter configuration based on the
// configuration and check used.
func (f *tokenintrospectFilter) String() string {
	switch f.typ {
	case checkOAuthTokenintrospectionAnyClaims:
		return fmt.Sprintf("%s(%s)", OAuthTokenintrospectionAnyClaimsName, f.kv)
	case checkOAuthTokenintrospectionAllClaims:
		return fmt.Sprintf("%s(%s)", OAuthTokenintrospectionAllClaimsName, f.kv)
	case checkOAuthTokenintrospectionAnyKV:
		return fmt.Sprintf("%s(%s)", OAuthTokenintrospectionAnyKVName, f.kv)
	case checkOAuthTokenintrospectionAllKV:
		return fmt.Sprintf("%s(%s)", OAuthTokenintrospectionAllKVName, f.kv)
	}
	return AuthUnknown
}

func (f *tokenintrospectFilter) validateAllKV(info tokenIntrospectionInfo) bool {
	for k, v := range f.kv {
		v2, ok := info[k].(string)
		if !ok || v != v2 {
			return false
		}
	}
	return true
}

func (f *tokenintrospectFilter) validateAnyKV(info tokenIntrospectionInfo) bool {
	for k, v := range f.kv {
		v2, ok := info[k].(string)
		if ok && v == v2 {
			return true
		}
	}
	return false
}

func (f *tokenintrospectFilter) Request(ctx filters.FilterContext) {
	r := ctx.Request()

	var info tokenIntrospectionInfo
	infoTemp, ok := ctx.StateBag()[tokenintrospectionCacheKey]
	if !ok {
		token, err := getToken(r)
		if err != nil {
			unauthorized(ctx, "", missingToken, f.authClient.url.Hostname())
			return
		}
		if token == "" {
			unauthorized(ctx, "", missingToken, f.authClient.url.Hostname())
			return
		}

		info, err = f.authClient.getTokenintrospect(token)
		if err != nil {
			reason := authServiceAccess
			if err == errInvalidToken {
				reason = invalidToken
			}
			unauthorized(ctx, "", reason, f.authClient.url.Hostname())
			return
		}
	} else {
		info = infoTemp.(tokenIntrospectionInfo)
	}

	log.Debugf("info: %#v", info)

	sub, err := info.Sub()
	if err != nil {
		unauthorized(ctx, sub, invalidSub, f.authClient.url.Hostname())
	}

	if !info.Active() {
		unauthorized(ctx, sub, inactiveToken, f.authClient.url.Hostname())
	}

	var allowed bool
	switch f.typ {
	case checkOAuthTokenintrospectionAnyClaims:
		fallthrough
	case checkOAuthTokenintrospectionAnyKV:
		allowed = f.validateAnyKV(info)
	case checkOAuthTokenintrospectionAllClaims:
		fallthrough
	case checkOAuthTokenintrospectionAllKV:
		allowed = f.validateAllKV(info)
	default:
		log.Errorf("Wrong tokenintrospectionFilter type: %s", f)
	}

	if !allowed {
		unauthorized(ctx, sub, invalidClaim, f.authClient.url.Hostname())
	} else {
		authorized(ctx, sub)
	}
	ctx.StateBag()[tokeninfoCacheKey] = info
}
func (f *tokenintrospectFilter) Response(filters.FilterContext) {}

type (
	tokenOidcSpec struct {
		typ roleCheckType
	}

	tokenOidcFilter struct {
		typ        roleCheckType
		config     *oauth2.Config
		provider   *oidc.Provider
		verifier   *oidc.IDTokenVerifier
		claims     []string
		validity   time.Duration
		aead       cipher.AEAD
		nonce      []byte
		cookiename string
	}
)

func NewOAuthOidcUserInfos() filters.Spec { return &tokenOidcSpec{typ: checkOidcUserInfos} }
func NewOAuthOidcAnyClaims() filters.Spec { return &tokenOidcSpec{typ: checkOidcAnyClaims} }
func NewOAuthOidcAllClaims() filters.Spec { return &tokenOidcSpec{typ: checkOidcAllClaims} }

// CreateFilter creates an OpenID Connect authorization filter.
//
// first arg: a provider, for example "https://accounts.google.com",
//            which has the path /.well-known/openid-configuration
//
// Example:
//
//     tokenOidcSpec("https://accounts.google.com", "255788903420-c68l9ustnfqkvukessbn46d92tirvh6s.apps.googleusercontent.com", "hjY8LHp9bPe97hS0aqXGh_zL", "http://127.0.0.1:5556/auth/google/callback")
func (s *tokenOidcSpec) CreateFilter(args []interface{}) (filters.Filter, error) {
	sargs, err := getStrings(args)
	if err != nil {
		return nil, err
	}
	if len(sargs) < 4 {
		return nil, filters.ErrInvalidFilterParameters
	}

	providerURL, err := url.Parse(sargs[0])

	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, providerURL.String())
	if err != nil {
		log.Errorf("Failed to create new provider %s: %v", providerURL, err)
		return nil, filters.ErrInvalidFilterParameters
	}

	aesgcm, nonce, err := getCiphersuite()
	if err != nil {
		log.Errorf("Failed to create ciphersuite: %v", err)
		return nil, filters.ErrInvalidFilterParameters
	}

	h := sha256.New()
	for _, s := range sargs {
		h.Write([]byte(s))
	}
	byteSlice := h.Sum(nil)
	sargsHash := fmt.Sprintf("%x", byteSlice)[:8]

	f := &tokenOidcFilter{
		typ: s.typ,
		config: &oauth2.Config{
			ClientID:     sargs[1],
			ClientSecret: sargs[2],
			RedirectURL:  sargs[3], // self endpoint
			Endpoint:     provider.Endpoint(),
		},
		provider: provider,
		verifier: provider.Verifier(&oidc.Config{
			ClientID: sargs[1],
		}),
		validity:   1 * time.Hour,
		aead:       aesgcm,
		nonce:      nonce,
		cookiename: oauthOidcCookieName + sargsHash,
	}
	f.config.Scopes = []string{oidc.ScopeOpenID}

	switch f.typ {
	case checkOidcUserInfos:
		if len(sargs) > 4 { // google IAM needs a scope to be sent
			f.config.Scopes = append(f.config.Scopes, sargs[4:]...)
		} else {
			// Scope check is required for auth code flow
			return nil, filters.ErrInvalidFilterParameters
		}
	case checkOidcAnyClaims:
		fallthrough
	case checkOidcAllClaims:
		f.config.Scopes = append(f.config.Scopes, sargs[4:]...)
		f.claims = sargs[4:]
	}
	return f, nil
}

func (s *tokenOidcSpec) Name() string {
	switch s.typ {
	case checkOidcUserInfos:
		return OidcUserInfoName
	case checkOidcAnyClaims:
		return OidcAnyClaimsName
	case checkOidcAllClaims:
		return OidcAllClaimsName
	}
	return AuthUnknown
}

func (f *tokenOidcFilter) validateAnyClaims(h map[string]interface{}) bool {
	if len(f.claims) == 0 {
		return true
	}

	var a []string
	for k, _ := range h {
		a = append(a, k)
	}

	return intersect(f.claims, a)
}

func (f *tokenOidcFilter) validateAllClaims(h map[string]interface{}) bool {
	if len(f.claims) == 0 {
		return true
	}

	var a []string
	for k, _ := range h {
		a = append(a, k)
	}

	log.Infof("all(%v, %v)", f.claims, a)
	return all(f.claims, a)
}

const (
	secretSize    = 20
	letterBytes   = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

var (
	src      = rand.NewSource(time.Now().UnixNano())
	stateMap = make(map[string]bool)
)

// https://stackoverflow.com/questions/22892120/how-to-generate-a-random-string-of-a-fixed-length-in-golang
func randString(n int) string {
	b := make([]byte, n)
	// A src.Int63() generates 63 random bits, enough for letterIdxMax characters!
	for i, cache, remain := n-1, src.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return string(b)
}

func getCiphersuite() (cipher.AEAD, []byte, error) {
	password := getPassword()
	salt := getSalt()
	nonce := getNonce()

	key, err := scrypt.Key(password, salt, 1<<15, 8, 1, 32)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create key: %v", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create new cipher: %v", err)
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create new GCM: %v", err)
	}
	return aesgcm, nonce, nil
}

// getPassword returns a secret byte slice to use as secret encryption key
// TODO(sszuecs): add enc/dec cipher support and get all keymaterial from trusted sources
func getPassword() []byte {
	return []byte("supersecret")
}

// getSalt returns an 8 byte salt
// TODO(sszuecs): get salt from trusted sources
func getSalt() []byte {
	return []byte{0xc8, 0x28, 0xf2, 0x58, 0xa7, 0x6a, 0xad, 0x7b}
}

// getNonce returns a 12 byte nonce
// TODO(sszuecs): get nonce from trusted sources
// 2^32 > 4b requests, might be ok without rotation
func getNonce() []byte {
	return []byte{0xde, 0xad, 0xbe, 0xef, 0xc8, 0x28, 0xf2, 0x58, 0xa7, 0x6a, 0xad, 0x7b}
}

func getTimestampFromState(b []byte, nonceLength int) time.Time {
	ts := string(b[secretSize : len(b)-nonceLength])
	i, err := strconv.Atoi(ts)
	if err != nil {
		return time.Time{}
	}
	return time.Unix(int64(i), 0)

}
func createState(nonce string) string {
	return randString(secretSize) + fmt.Sprintf("%d", time.Now().Add(1*time.Minute).Unix()) + nonce
}

func (f *tokenOidcFilter) doRedirect(ctx filters.FilterContext) {
	statePlain := createState(fmt.Sprintf("%x", f.nonce))
	stateEnc := f.aead.Seal(nil, f.nonce, []byte(statePlain), nil)
	log.Infof("serve redirect: state:%s", statePlain)
	ctx.Serve(&http.Response{
		Header: http.Header{
			"Location": []string{f.config.AuthCodeURL(fmt.Sprintf("%x", stateEnc))},
		},
		StatusCode: http.StatusFound,
		Status:     "Moved Temporarily",
	})
}

// Response saves our state bag in a cookie, such that we can get it
// back in supsequent requests to handle the requests.
func (f *tokenOidcFilter) Response(ctx filters.FilterContext) {
	if v, ok := ctx.StateBag()[oidcStatebagKey]; ok {
		state, ok := v.(string)
		if !ok {
			return
		}
		cookie := &http.Cookie{
			Name:     f.cookiename,
			Value:    state,
			Secure:   true,
			HttpOnly: false,
			Path:     "/",
			Domain:   ctx.Request().Host,
			MaxAge:   int(f.validity.Seconds()),
			Expires:  time.Now().Add(f.validity),
		}
		http.SetCookie(ctx.ResponseWriter(), cookie)
	}
}

func (f *tokenOidcFilter) Request(ctx filters.FilterContext) {
	var state string
	log.Infof("tokenOidcFilter got a request")
	r := ctx.Request()

	// CSRF protection using similar to
	// https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet#Encrypted_Token_Pattern,
	// because of
	// https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
	stateQueryEncHex := r.URL.Query().Get("state")
	stateQueryEnc := make([]byte, len(stateQueryEncHex))
	if _, err := fmt.Sscanf(stateQueryEncHex, "%x", &stateQueryEnc); err != nil && err != io.EOF {
		log.Fatalf("Failed to sscanf: %v", err)
	}
	stateQueryPlain, err := f.aead.Open(nil, f.nonce, stateQueryEnc, nil)
	if err != nil {
		f.doRedirect(ctx)
		return
	}
	if time.Now().After(getTimestampFromState(stateQueryPlain, len(fmt.Sprintf("%x", f.nonce)))) {
		// state query is older than allowed -> enforce login
		f.doRedirect(ctx)
		return
	}

	log.Infof("do exchange\n========= failure after this are fine =======")
	// authcode flow
	oauth2Token, err := f.config.Exchange(r.Context(), r.URL.Query().Get("code"))
	if err != nil {
		// TODO(sszuecs) review error handling
		unauthorized(ctx, "Failed to exchange token: "+err.Error()+", state: "+state, invalidClaim, r.Host)
		return
	}

	if !oauth2Token.Valid() {
		unauthorized(ctx, "invalid token", invalidToken, r.Host)
		return
	}

	// encrypt(bas64(full token data)) and put it into a set-cookie and put into state bag

	var (
		allowed bool
		data    []byte
		sub     string
	)
	switch f.typ {
	case checkOidcUserInfos:
		userInfo, err := f.provider.UserInfo(r.Context(), oauth2.StaticTokenSource(oauth2Token))
		if err != nil {
			unauthorized(ctx, "Failed to get userinfo: "+err.Error(), invalidToken, r.Host)
			return
		}
		sub = userInfo.Subject

		resp := struct {
			OAuth2Token *oauth2.Token
			UserInfo    *oidc.UserInfo
		}{oauth2Token, userInfo}
		data, err = json.Marshal(resp)
		if err != nil {
			unauthorized(ctx, fmt.Sprintf("Failed to marshal userinfo backend data for sub=%s: %v", sub, err), invalidToken, r.Host)
			return
		}

		allowed = true // nothing to do

	case checkOidcAnyClaims:
		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			unauthorized(ctx, "No id_token field in oauth2 token", invalidToken, r.Host)
			return
		}
		idToken, err := f.verifier.Verify(r.Context(), rawIDToken)
		if err != nil {
			unauthorized(ctx, "Failed to verify ID Token: "+err.Error(), invalidToken, r.Host)
			return
		}

		tokenMap := make(map[string]interface{})
		if err := idToken.Claims(&tokenMap); err != nil {
			unauthorized(ctx, "Failed to get claims: "+err.Error(), invalidToken, r.Host)
			return
		}

		sub, ok = tokenMap["sub"].(string)
		if !ok {
			unauthorized(ctx, "Failed to get sub", invalidToken, r.Host)
			return
		}

		resp := struct {
			OAuth2Token *oauth2.Token
			TokenMap    map[string]interface{}
		}{oauth2Token, tokenMap}
		data, err = json.Marshal(resp)
		if err != nil {
			unauthorized(ctx, fmt.Sprintf("Failed to prepare data for backend with sub=%s: %v", sub, err), invalidToken, r.Host)
			return
		}

		allowed = f.validateAnyClaims(tokenMap)

	case checkOidcAllClaims:
		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			unauthorized(ctx, "No id_token field in oauth2 token", invalidToken, r.Host)
			return
		}
		idToken, err := f.verifier.Verify(r.Context(), rawIDToken)
		if err != nil {
			unauthorized(ctx, "Failed to verify ID Token: "+err.Error(), invalidToken, r.Host)
			return
		}

		tokenMap := make(map[string]interface{})
		if err := idToken.Claims(&tokenMap); err != nil {
			unauthorized(ctx, "Failed to get claims: "+err.Error(), invalidToken, r.Host)
			return
		}

		sub, ok = tokenMap["sub"].(string)
		if !ok {
			unauthorized(ctx, "Failed to get sub", invalidToken, r.Host)
			return
		}

		resp := struct {
			OAuth2Token *oauth2.Token
			TokenMap    map[string]interface{}
		}{oauth2Token, tokenMap}
		data, err = json.Marshal(resp)
		if err != nil {
			unauthorized(ctx, fmt.Sprintf("Failed to prepare data for backend with sub=%s: %v", sub, err), invalidToken, r.Host)
			return
		}

		allowed = f.validateAllClaims(tokenMap)
		log.Infof("validateAllClaims: %v", allowed)
	default:
		log.Errorf("Wrong tokeninfoFilter type: %s", f)
	}

	if !allowed {
		log.Infof("unauthorized")
		// TODO(sszuecs) review error handling
		unauthorized(ctx, sub, invalidClaim, r.Host)
		return
	}

	encryptedData := encryptData(f.aead, f.nonce, data)
	ctx.StateBag()[oidcStatebagKey] = encryptedData

	log.Infof("send authorized")
	authorized(ctx, sub)
}

func encryptData(aead cipher.AEAD, nonce, plaintext []byte) []byte {
	ciphertext := aead.Seal(nil, nonce, plaintext, nil)
	log.Infof("plaintext: %s\nciphertext: %x\n", plaintext, ciphertext)
	return ciphertext
}
