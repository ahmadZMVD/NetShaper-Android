package engine

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// TunnelProperties holds Microsoft Dev Tunnels credentials returned by GitHub Codespaces API.
type TunnelProperties struct {
	ConnectAccessToken     string   `json:"connect_access_token"`
	ManagePortsAccessToken string   `json:"manage_ports_access_token"`
	ServiceURI             string   `json:"service_uri"`
	TunnelID               string   `json:"tunnel_id"`
	ClusterID              string   `json:"cluster_id"`
	Domain                 string   `json:"domain"`
	HostPublicKeys         []string `json:"host_public_keys,omitempty"`
}

type CodespaceMachine struct {
	Name           string `json:"name"`
	DisplayName    string `json:"display_name"`
	CPUs           int    `json:"cpus"`
	MemoryInBytes  int64  `json:"memory_in_bytes"`
	StorageInBytes int64  `json:"storage_in_bytes"`
}

type CodespaceSummary struct {
	Name        string           `json:"name"`
	DisplayName string           `json:"display_name"`
	State       string           `json:"state"`
	OwnerLogin  string           `json:"owner_login"`
	Repository  string           `json:"repository"`
	Machine     CodespaceMachine `json:"machine"`
}

type CodespaceDetail struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	State       string `json:"state"`
	Owner       struct {
		Login string `json:"login"`
	} `json:"owner"`
	Repository struct {
		FullName string `json:"full_name"`
	} `json:"repository"`
	Machine    CodespaceMachine `json:"machine"`
	Connection struct {
		TunnelProperties TunnelProperties `json:"tunnel_properties"`
	} `json:"connection"`
}

type DeviceAuthStartResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

type DeviceAuthPollResponse struct {
	Status      string `json:"status"` // "authorized" | "pending" | "slow_down" | "expired" | "denied" | "error"
	AccessToken string `json:"access_token,omitempty"`
	TokenType   string `json:"token_type,omitempty"`
	Scope       string `json:"scope,omitempty"`
	Error       string `json:"error,omitempty"`
	Interval    int    `json:"interval,omitempty"`
}

type QuotaInfo struct {
	Checked           bool   `json:"checked"`
	CheckedAt         string `json:"checked_at,omitempty"`
	CodespaceName     string `json:"codespace_name"`
	CodespaceState    string `json:"codespace_state"`
	MachineName       string `json:"machine_name"`
	MachineDisplay    string `json:"machine_display"`
	CPUs              int    `json:"cpus"`
	MemoryGB          int    `json:"memory_gb"`
	StorageGB         int    `json:"storage_gb"`
	BillingAvailable  bool   `json:"billing_available"`
	CoreHoursUsed     float64 `json:"core_hours_used"`
	CoreHoursIncluded float64 `json:"core_hours_included"`
	BillingNote       string `json:"billing_note,omitempty"`
	GuardBlocked      string `json:"guard_blocked,omitempty"`
	Error             string `json:"error,omitempty"`
}

// ParseJWTExpiryLocally extracts the `exp` claim from a JWT without making any network calls.
func ParseJWTExpiryLocally(jwtToken string) (time.Time, bool) {
	parts := strings.Split(strings.TrimSpace(jwtToken), ".")
	if len(parts) < 2 {
		return time.Time{}, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}, false
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Exp <= 0 {
		return time.Time{}, false
	}
	return time.Unix(claims.Exp, 0).UTC(), true
}

// GitHubAPIClient executes GitHub REST and OAuth Device Flow calls over AntiPoisonResolver,
// routing all Codespaces control-plane calls through GitHubGuard.
type GitHubAPIClient struct {
	apiBaseURL   string
	oauthBaseURL string
	httpClient   *http.Client
	guard        *GitHubGuard
	coldPollWait []time.Duration
}

func NewGitHubAPIClient(apiBaseURL, oauthBaseURL string, resolver *AntiPoisonResolver, guard *GitHubGuard) *GitHubAPIClient {
	if strings.TrimSpace(apiBaseURL) == "" {
		apiBaseURL = DefaultGitHubAPIBaseURL
	}
	if strings.TrimSpace(oauthBaseURL) == "" {
		oauthBaseURL = DefaultGitHubOAuthBaseURL
	}
	if resolver == nil {
		resolver = NewAntiPoisonResolver(nil, nil)
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return resolver.DialContext(ctx, network, addr, 10*time.Second, DefaultTCPKeepAlivePeriod, DefaultTCPUserTimeout)
		},
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second,
		MaxIdleConns:          8,
		IdleConnTimeout:       60 * time.Second,
	}
	return &GitHubAPIClient{
		apiBaseURL:   strings.TrimRight(apiBaseURL, "/"),
		oauthBaseURL: strings.TrimRight(oauthBaseURL, "/"),
		httpClient:   &http.Client{Transport: tr, Timeout: 30 * time.Second},
		guard:        guard,
		coldPollWait: []time.Duration{12 * time.Second, 10 * time.Second, 15 * time.Second},
	}
}

func (c *GitHubAPIClient) SetColdPollDelays(delays []time.Duration) {
	if len(delays) > 0 {
		c.coldPollWait = delays
	}
}

func (c *GitHubAPIClient) CloseIdleConnections() {
	if c == nil || c.httpClient == nil {
		return
	}
	if tr, ok := c.httpClient.Transport.(*http.Transport); ok {
		tr.CloseIdleConnections()
	}
}

func (c *GitHubAPIClient) doJSON(ctx context.Context, method, fullURL, token string, body []byte, guardReason string, useGuard bool) (int, http.Header, []byte, error) {
	if useGuard && c.guard != nil {
		if err := c.guard.Allow(ctx, guardReason); err != nil {
			return 0, nil, nil, err
		}
	}
	var bodyReader io.Reader
	if len(body) > 0 {
		bodyReader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, fullURL, bodyReader)
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header.Set("User-Agent", "NetShaper-Mobile/7.0")
	req.Header.Set("Accept", "application/vnd.github+json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(token))
	}
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return resp.StatusCode, resp.Header, nil, err
	}
	if useGuard && c.guard != nil {
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			c.guard.RecordSuccess()
		} else {
			c.guard.RecordHTTPResponse(resp.StatusCode, resp.Header, string(raw))
		}
	}
	return resp.StatusCode, resp.Header, raw, nil
}

func (c *GitHubAPIClient) formatHTTPError(status int, hdr http.Header, body []byte, contextDesc string) error {
	detail := fmt.Sprintf("%s: HTTP %d: %s", contextDesc, status, strings.TrimSpace(string(body)))
	if hdr != nil {
		if ra := strings.TrimSpace(hdr.Get("Retry-After")); ra != "" {
			detail += " Retry-After: " + ra
		}
	}
	if fatal := ClassifyPermanentBootError(detail); fatal != nil {
		return fatal
	}
	return errors.New(RedactSecrets(detail))
}

// StartDeviceAuth initiates GitHub OAuth Device Flow (`codespace` scope) with zero GMS dependency.
func (c *GitHubAPIClient) StartDeviceAuth(ctx context.Context, clientID string) (DeviceAuthStartResponse, error) {
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		return DeviceAuthStartResponse{}, errors.New("oauth client_id must not be empty")
	}
	form := url.Values{}
	form.Set("client_id", clientID)
	form.Set("scope", "codespace read:user")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.oauthBaseURL+"/login/device/code", strings.NewReader(form.Encode()))
	if err != nil {
		return DeviceAuthStartResponse{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "NetShaper-Mobile/7.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return DeviceAuthStartResponse{}, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil {
		return DeviceAuthStartResponse{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return DeviceAuthStartResponse{}, fmt.Errorf("device auth start HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var out DeviceAuthStartResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return DeviceAuthStartResponse{}, fmt.Errorf("parse device auth start: %w", err)
	}
	if out.DeviceCode == "" || out.UserCode == "" {
		return DeviceAuthStartResponse{}, errors.New("github device auth response missing device_code or user_code")
	}
	return out, nil
}

// PollDeviceAuth performs one non-blocking poll of GitHub's device token endpoint.
func (c *GitHubAPIClient) PollDeviceAuth(ctx context.Context, clientID, deviceCode string) (DeviceAuthPollResponse, error) {
	form := url.Values{}
	form.Set("client_id", strings.TrimSpace(clientID))
	form.Set("device_code", strings.TrimSpace(deviceCode))
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.oauthBaseURL+"/login/oauth/access_token", strings.NewReader(form.Encode()))
	if err != nil {
		return DeviceAuthPollResponse{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "NetShaper-Mobile/7.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return DeviceAuthPollResponse{}, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil {
		return DeviceAuthPollResponse{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return DeviceAuthPollResponse{Status: "error", Error: fmt.Sprintf("HTTP %d", resp.StatusCode)}, nil
	}
	var doc struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		Scope       string `json:"scope"`
		Error       string `json:"error"`
		ErrorDesc   string `json:"error_description"`
		Interval    int    `json:"interval"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return DeviceAuthPollResponse{}, err
	}
	if doc.AccessToken != "" {
		return DeviceAuthPollResponse{
			Status:      "authorized",
			AccessToken: doc.AccessToken,
			TokenType:   doc.TokenType,
			Scope:       doc.Scope,
		}, nil
	}
	switch doc.Error {
	case "authorization_pending":
		return DeviceAuthPollResponse{Status: "pending"}, nil
	case "slow_down":
		return DeviceAuthPollResponse{Status: "slow_down", Interval: doc.Interval}, nil
	case "expired_token":
		return DeviceAuthPollResponse{Status: "expired", Error: doc.ErrorDesc}, nil
	case "access_denied":
		return DeviceAuthPollResponse{Status: "denied", Error: doc.ErrorDesc}, nil
	default:
		return DeviceAuthPollResponse{Status: "error", Error: doc.Error + ": " + doc.ErrorDesc}, nil
	}
}

// GetCodespaceConnection fetches internal Dev Tunnels connection properties for a Codespace.
func (c *GitHubAPIClient) GetCodespaceConnection(ctx context.Context, token, name string) (CodespaceDetail, error) {
	u := fmt.Sprintf("%s/user/codespaces/%s?internal=true&refresh=true", c.apiBaseURL, url.PathEscape(name))
	status, hdr, raw, err := c.doJSON(ctx, http.MethodGet, u, token, nil, "get_codespace:"+name, true)
	if err != nil {
		return CodespaceDetail{}, err
	}
	if status < 200 || status >= 300 {
		return CodespaceDetail{}, c.formatHTTPError(status, hdr, raw, "get codespace")
	}
	var detail CodespaceDetail
	if err := json.Unmarshal(raw, &detail); err != nil {
		return CodespaceDetail{}, fmt.Errorf("decode codespace detail: %w", err)
	}
	return detail, nil
}

// StartCodespace issues POST /user/codespaces/{name}/start through GitHubGuard.
func (c *GitHubAPIClient) StartCodespace(ctx context.Context, token, name string) (CodespaceDetail, error) {
	u := fmt.Sprintf("%s/user/codespaces/%s/start", c.apiBaseURL, url.PathEscape(name))
	status, hdr, raw, err := c.doJSON(ctx, http.MethodPost, u, token, nil, "start_codespace:"+name, true)
	if err != nil {
		return CodespaceDetail{}, err
	}
	if status < 200 || status >= 300 {
		return CodespaceDetail{}, c.formatHTTPError(status, hdr, raw, "start codespace")
	}
	var detail CodespaceDetail
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &detail)
	}
	return detail, nil
}

// EnsureAvailableAndFetchTunnel performs adaptive cold-boot polling (strictly 3-4 API calls out of 6/5m budget)
// to wake a Shutdown Codespace and return fresh Dev Tunnels TunnelProperties.
func (c *GitHubAPIClient) EnsureAvailableAndFetchTunnel(ctx context.Context, token, name string) (CodespaceDetail, error) {
	detail, err := c.GetCodespaceConnection(ctx, token, name)
	if err != nil {
		return CodespaceDetail{}, err
	}
	if strings.EqualFold(detail.State, "Available") && detail.Connection.TunnelProperties.ConnectAccessToken != "" {
		return detail, nil
	}

	lowState := strings.ToLower(strings.TrimSpace(detail.State))
	if lowState == "shutdown" || lowState == "stopped" || lowState == "unavailable" {
		if _, err := c.StartCodespace(ctx, token, name); err != nil {
			return CodespaceDetail{}, err
		}
	}

	for _, waitDur := range c.coldPollWait {
		tm := time.NewTimer(waitDur)
		select {
		case <-ctx.Done():
			tm.Stop()
			return CodespaceDetail{}, ctx.Err()
		case <-tm.C:
		}
		detail, err = c.GetCodespaceConnection(ctx, token, name)
		if err != nil {
			return CodespaceDetail{}, err
		}
		if strings.EqualFold(detail.State, "Available") && detail.Connection.TunnelProperties.ConnectAccessToken != "" {
			return detail, nil
		}
	}
	return CodespaceDetail{}, fmt.Errorf("codespace %q did not reach Available state (last=%q)", name, detail.State)
}

// StopCodespace issues POST /user/codespaces/{name}/stop.
func (c *GitHubAPIClient) StopCodespace(ctx context.Context, token, name string) error {
	u := fmt.Sprintf("%s/user/codespaces/%s/stop", c.apiBaseURL, url.PathEscape(name))
	status, hdr, raw, err := c.doJSON(ctx, http.MethodPost, u, token, nil, "stop_codespace:"+name, false)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return c.formatHTTPError(status, hdr, raw, "stop codespace")
	}
	if c.guard != nil {
		c.guard.MarkCodespaceState("Shutdown")
	}
	return nil
}

// ListCodespaces queries GET /user/codespaces cleanly through GitHubGuard.
func (c *GitHubAPIClient) ListCodespaces(ctx context.Context, token string) ([]CodespaceSummary, error) {
	u := c.apiBaseURL + "/user/codespaces"
	status, hdr, raw, err := c.doJSON(ctx, http.MethodGet, u, token, nil, "list_codespaces", true)
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 300 {
		return nil, c.formatHTTPError(status, hdr, raw, "list codespaces")
	}
	var doc struct {
		Codespaces []CodespaceDetail `json:"codespaces"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parse codespaces list: %w", err)
	}
	out := make([]CodespaceSummary, 0, len(doc.Codespaces))
	for _, cs := range doc.Codespaces {
		out = append(out, CodespaceSummary{
			Name:        cs.Name,
			DisplayName: cs.DisplayName,
			State:       cs.State,
			OwnerLogin:  cs.Owner.Login,
			Repository:  cs.Repository.FullName,
			Machine:     cs.Machine,
		})
	}
	return out, nil
}

// CheckQuota executes on-demand Codespaces machine tier + optional billing check,
// isolating missing billing-scope HTTP 403 from GitHubGuard WAF penalties.
func (c *GitHubAPIClient) CheckQuota(ctx context.Context, token, targetName string) (QuotaInfo, error) {
	out := QuotaInfo{
		Checked:       true,
		CheckedAt:     time.Now().UTC().Format(time.RFC3339),
		CodespaceName: targetName,
	}
	if c.guard != nil {
		ok, wait, why := c.guard.TryAllow("quota_codespaces")
		if !ok {
			out.GuardBlocked = fmt.Sprintf("Blocked by WAF guard (%s, wait %s)", why, wait.Round(time.Second))
			return out, nil
		}
	}
	status, hdr, raw, err := c.doJSON(ctx, http.MethodGet, c.apiBaseURL+"/user/codespaces", token, nil, "", false)
	if err != nil {
		out.Error = RedactSecrets(err.Error())
		return out, err
	}
	if status < 200 || status >= 300 {
		msg := fmt.Sprintf("HTTP %d: %s", status, strings.TrimSpace(string(raw)))
		if c.guard != nil && IsQuotaRateLimitOrWAF(msg) {
			c.guard.RecordHTTPResponse(status, hdr, string(raw))
		}
		out.Error = RedactSecrets(msg)
		return out, errors.New(out.Error)
	}

	var doc struct {
		Codespaces []CodespaceDetail `json:"codespaces"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		out.Error = "invalid codespaces JSON"
		return out, err
	}
	if len(doc.Codespaces) == 0 {
		out.CodespaceState = "Not Found"
		out.Error = "no codespaces found on account"
		return out, nil
	}
	idx := 0
	for i, cs := range doc.Codespaces {
		if strings.EqualFold(cs.Name, targetName) {
			idx = i
			break
		}
	}
	cs := doc.Codespaces[idx]
	out.CodespaceName = cs.Name
	out.CodespaceState = cs.State
	out.MachineName = cs.Machine.Name
	out.MachineDisplay = cs.Machine.DisplayName
	if out.MachineDisplay == "" {
		out.MachineDisplay = cs.Machine.Name
	}
	out.CPUs = cs.Machine.CPUs
	out.MemoryGB = int(cs.Machine.MemoryInBytes / (1024 * 1024 * 1024))
	out.StorageGB = int(cs.Machine.StorageInBytes / (1024 * 1024 * 1024))

	owner := strings.TrimSpace(cs.Owner.Login)
	if owner == "" {
		out.BillingNote = "Showing machine tier"
		return out, nil
	}

	if c.guard != nil {
		ok, wait, why := c.guard.TryAllow("quota_billing")
		if !ok && why == "min_call_spacing" && wait > 0 && wait <= 3*time.Second {
			tm := time.NewTimer(wait + 25*time.Millisecond)
			select {
			case <-tm.C:
				ok, _, why = c.guard.TryAllow("quota_billing")
			case <-ctx.Done():
				tm.Stop()
				return out, ctx.Err()
			}
		}
		if !ok {
			out.BillingNote = fmt.Sprintf("Billing check skipped (%s) — showing machine tier", why)
			return out, nil
		}
	}

	bURL := fmt.Sprintf("%s/users/%s/settings/billing/usage", c.apiBaseURL, url.PathEscape(owner))
	bStatus, bHdr, bRaw, bErr := c.doJSON(ctx, http.MethodGet, bURL, token, nil, "", false)
	if bErr == nil && bStatus >= 200 && bStatus < 300 {
		if used, inc, ok := parseBillingUsageJSON(bRaw); ok {
			out.BillingAvailable = true
			out.CoreHoursUsed = used
			out.CoreHoursIncluded = inc
			out.BillingNote = "Live GitHub billing usage"
		} else {
			out.BillingNote = "No Codespaces billing items reported — showing machine tier"
		}
		return out, nil
	}

	bMsg := fmt.Sprintf("HTTP %d: %s", bStatus, strings.TrimSpace(string(bRaw)))
	if bErr != nil {
		bMsg = bErr.Error()
	}
	if IsQuotaRateLimitOrWAF(bMsg) {
		if c.guard != nil {
			c.guard.RecordHTTPResponse(bStatus, bHdr, string(bRaw))
		}
		out.BillingNote = "Billing query rate-limited (WAF guard engaged)"
	} else if IsQuotaBillingScope403(bMsg) {
		out.BillingNote = "Billing scope unavailable (HTTP 403) — showing machine tier"
	} else {
		out.BillingNote = "Billing endpoint unavailable — showing machine tier"
	}
	return out, nil
}

func parseBillingUsageJSON(raw []byte) (float64, float64, bool) {
	var doc struct {
		UsageItems []struct {
			Product  string  `json:"product"`
			Quantity float64 `json:"quantity"`
			UnitType string  `json:"unitType"`
		} `json:"usageItems"`
		TotalMinutesUsed   float64 `json:"total_minutes_used"`
		IncludedMinutes    float64 `json:"included_minutes"`
		TotalCoreHoursUsed float64 `json:"total_core_hours_used"`
		IncludedCoreHours  float64 `json:"included_core_hours"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return 0, 0, false
	}
	if doc.TotalCoreHoursUsed > 0 || doc.IncludedCoreHours > 0 {
		return round2(doc.TotalCoreHoursUsed), round2(doc.IncludedCoreHours), true
	}
	if doc.TotalMinutesUsed > 0 || doc.IncludedMinutes > 0 {
		return round2(doc.TotalMinutesUsed / 60.0), round2(doc.IncludedMinutes / 60.0), true
	}
	var sum float64
	found := false
	for _, it := range doc.UsageItems {
		if strings.Contains(strings.ToLower(it.Product), "codespace") && strings.Contains(strings.ToLower(it.UnitType), "hour") {
			sum += it.Quantity
			found = true
		}
	}
	if found {
		return round2(sum), 120.0, true
	}
	return 0, 0, false
}

// CredentialManager shares one fresh Dev Tunnels TunnelProperties JWT across all pool workers
// using strict singleflight refresh and local zero-API JWT `exp` validation.
type CredentialManager struct {
	api           *GitHubAPIClient
	token         string
	codespaceName string
	refreshMargin time.Duration
	nowFn         func() time.Time

	mu        sync.Mutex
	cached    TunnelProperties
	expiresAt time.Time
	hasCached bool
	inFlight  *credFlight
}

type credFlight struct {
	done chan struct{}
	res  TunnelProperties
	err  error
}

func NewCredentialManager(api *GitHubAPIClient, token, codespaceName string) *CredentialManager {
	return &CredentialManager{
		api:           api,
		token:         strings.TrimSpace(token),
		codespaceName: strings.TrimSpace(codespaceName),
		refreshMargin: 10 * time.Minute,
		nowFn:         time.Now,
	}
}

// Invalidate clears the cached JWT (called when Dev Tunnels relay rejects with HTTP 401/403).
func (m *CredentialManager) Invalidate() {
	m.mu.Lock()
	m.hasCached = false
	m.expiresAt = time.Time{}
	m.cached = TunnelProperties{}
	m.mu.Unlock()
}

// Get returns a valid cached TunnelProperties with 0 API calls, or joins/executes ONE singleflight refresh.
func (m *CredentialManager) Get(ctx context.Context, forceRefresh bool) (TunnelProperties, error) {
	for {
		m.mu.Lock()
		now := m.nowFn()
		if !forceRefresh && m.hasCached && now.Add(m.refreshMargin).Before(m.expiresAt) {
			cp := m.cached
			m.mu.Unlock()
			return cp, nil
		}
		if m.inFlight != nil {
			flight := m.inFlight
			m.mu.Unlock()
			select {
			case <-flight.done:
				if flight.err != nil {
					return TunnelProperties{}, flight.err
				}
				return flight.res, nil
			case <-ctx.Done():
				return TunnelProperties{}, ctx.Err()
			}
		}
		flight := &credFlight{done: make(chan struct{})}
		m.inFlight = flight
		m.mu.Unlock()

		detail, err := m.api.EnsureAvailableAndFetchTunnel(ctx, m.token, m.codespaceName)
		var props TunnelProperties
		if err == nil {
			props = detail.Connection.TunnelProperties
			if props.ConnectAccessToken == "" || props.TunnelID == "" {
				err = errors.New("github codespace API returned empty tunnel_properties")
			}
		}

		m.mu.Lock()
		if err == nil {
			m.cached = props
			m.hasCached = true
			if exp, ok := ParseJWTExpiryLocally(props.ConnectAccessToken); ok {
				m.expiresAt = exp
			} else {
				m.expiresAt = m.nowFn().Add(45 * time.Minute)
			}
		}
		flight.res = props
		flight.err = err
		m.inFlight = nil
		close(flight.done)
		m.mu.Unlock()

		return props, err
	}
}

