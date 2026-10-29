package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode"
)

const (
	cfAPIBase                  = "https://api.cloudflare.com/client/v4"
	defaultManagedHTTPDDoSID   = "4d21379b4f9f4bb088e0729962c8b3cf"
	defaultEdgeTuneTimeout     = 90 * time.Second
	defaultSingleReqTimeout    = 12 * time.Second
	defaultZoneDiscoverTimeout = 10 * time.Second
	bermudaLCCommentPrefix     = "bermuda-lc:"
	legacyRWCommentPrefix      = "bermuda-rw:"
)

type cfAPIMsg struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type cfEnvelope[T any] struct {
	Success  bool       `json:"success"`
	Errors   []cfAPIMsg `json:"errors"`
	Messages []cfAPIMsg `json:"messages"`
	Result   T          `json:"result"`
}

type cfAPIError struct {
	StatusCode int
	Errors     []cfAPIMsg
}

func (e *cfAPIError) Error() string {
	return fmt.Sprintf("cloudflare api error (HTTP %d): %+v", e.StatusCode, e.Errors)
}

func (e *cfAPIError) IsInvalidToken() bool {
	for _, msg := range e.Errors {
		if msg.Code == 9109 || msg.Code == 6003 || msg.Code == 9106 {
			return true
		}
		lower := strings.ToLower(msg.Message)
		if strings.Contains(lower, "invalid access token") || strings.Contains(lower, "invalid request headers") {
			return true
		}
	}
	return false
}

func (e *cfAPIError) IsPermissionOrPlan() bool {
	if e.StatusCode == http.StatusUnauthorized || e.StatusCode == http.StatusForbidden {
		return true
	}
	for _, msg := range e.Errors {
		if msg.Code == 50001 || msg.Code == 1003 {
			return true
		}
		lower := strings.ToLower(msg.Message)
		if strings.Contains(lower, "unauthorized") ||
			strings.Contains(lower, "not allowed") ||
			strings.Contains(lower, "permission") ||
			strings.Contains(lower, "entitlement") ||
			strings.Contains(lower, "subscription") ||
			strings.Contains(lower, "plan") ||
			strings.Contains(lower, "exceeded the maximum number of rules") ||
			strings.Contains(lower, "out of 0") {
			return true
		}
	}
	return false
}

type cfZoneDetails struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

type CloudflareClient struct {
	Token           string
	ZoneID          string
	apiBase         string
	preferredDomain string
	lucityOrigin    string
	client          *http.Client
	mu              sync.RWMutex
	cachedZone      string
	onTopology      func(lucityDom, cfDom string)
}

func sanitizeCloudflareToken(raw string) string {
	s := strings.TrimSpace(raw)
	upper := strings.ToUpper(s)
	for _, prefix := range []string{"CLOUDFLARE_API_TOKEN", "BERMUDA_CF_API_TOKEN", "CF_API_TOKEN"} {
		if strings.HasPrefix(upper, prefix) {
			if _, after, ok := strings.Cut(s, "="); ok {
				s = strings.TrimSpace(after)
			}
		}
	}
	if len(s) > 7 && strings.EqualFold(s[:7], "bearer ") {
		s = strings.TrimSpace(s[7:])
	}
	s = strings.Trim(s, "\"'` \t\r\n")
	s = strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) || unicode.IsControl(r) || r > 126 {
			return -1
		}
		return r
	}, s)
	if strings.Contains(s, "${{") || strings.HasPrefix(s, "$") {
		return ""
	}
	return s
}

func NewCloudflareClient(token, zoneID string) *CloudflareClient {
	cleanTok := sanitizeCloudflareToken(token)
	cleanZone := sanitizeExplicitCredential(zoneID)
	lcDom, _ := resolveInfrastructureDomains()
	if !isLucityPublicDomain(lcDom) {
		lcDom = ""
	}
	return &CloudflareClient{
		Token:        cleanTok,
		ZoneID:       cleanZone,
		apiBase:      cfAPIBase,
		lucityOrigin: lcDom,
		client: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

func extractCommentLucityDomain(comment string) string {
	comment = strings.TrimSpace(comment)
	lower := strings.ToLower(comment)
	for _, prefix := range []string{bermudaLCCommentPrefix, legacyRWCommentPrefix} {
		idx := strings.Index(lower, prefix)
		if idx == -1 {
			continue
		}
		rest := strings.TrimSpace(comment[idx+len(prefix):])
		if fields := strings.Fields(rest); len(fields) > 0 {
			rest = fields[0]
		}
		candidate := cleanHost(rest)
		if isFullLucityServiceDomain(candidate) {
			return candidate
		}
	}
	return ""
}

func (c *CloudflareClient) SetTopologyCallback(fn func(lucityDom, cfDom string)) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.onTopology = fn
	c.mu.Unlock()
}

func (c *CloudflareClient) notifyTopology() {
	if c == nil {
		return
	}
	c.mu.RLock()
	fn := c.onTopology
	lc := c.lucityOrigin
	cf := c.preferredDomain
	if cf == "" {
		cf = c.cachedZone
	}
	c.mu.RUnlock()
	if fn != nil {
		fn(lc, cf)
	}
}

func (c *CloudflareClient) SetPreferredDomain(d string) {
	if c == nil {
		return
	}
	clean := cleanHost(d)
	if clean == "" || isLucityManagedDomain(clean) {
		return
	}
	c.mu.Lock()
	c.preferredDomain = clean
	if c.cachedZone == "" || strings.HasSuffix(clean, "."+c.cachedZone) {
		c.cachedZone = clean
	}
	c.mu.Unlock()
}

func (c *CloudflareClient) SetLucityOrigin(d string) {
	if c == nil {
		return
	}
	clean := cleanHost(d)
	if !isLucityPublicDomain(clean) {
		return
	}
	c.mu.Lock()
	if c.lucityOrigin == "" || isFullLucityServiceDomain(clean) {
		c.lucityOrigin = clean
	}
	c.mu.Unlock()
}

func (c *CloudflareClient) GetLucityOrigin() string {
	if c == nil {
		return ""
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lucityOrigin
}

func (c *CloudflareClient) GetZoneID() string {
	if c == nil {
		return ""
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.ZoneID
}

func (c *CloudflareClient) baseURL() string {
	if c != nil && c.apiBase != "" {
		return c.apiBase
	}
	return cfAPIBase
}

func doCFRequest[T any](ctx context.Context, c *CloudflareClient, method, path string, body any) (T, error) {
	var zero T
	reqCtx, cancel := context.WithTimeout(ctx, defaultSingleReqTimeout)
	defer cancel()

	var reqBody io.Reader
	if body != nil {
		rawJSON, err := json.Marshal(body)
		if err != nil {
			return zero, fmt.Errorf("marshal payload: %w", err)
		}
		reqBody = bytes.NewReader(rawJSON)
	}

	req, err := http.NewRequestWithContext(reqCtx, method, c.baseURL()+path, reqBody)
	if err != nil {
		return zero, fmt.Errorf("build request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "BERMUDA-Portal-EdgeOrchestrator/4.0 (Go-Standard-Library)")

	resp, err := c.client.Do(req)
	if err != nil {
		return zero, err
	}
	defer resp.Body.Close()

	rawBytes, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return zero, fmt.Errorf("read response body: %w", err)
	}

	var env cfEnvelope[T]
	if err := json.Unmarshal(rawBytes, &env); err != nil {
		return zero, &cfAPIError{
			StatusCode: resp.StatusCode,
			Errors: []cfAPIMsg{{
				Code:    resp.StatusCode,
				Message: string(rawBytes[:min(len(rawBytes), 256)]),
			}},
		}
	}

	if resp.StatusCode >= 400 || !env.Success {
		return zero, &cfAPIError{
			StatusCode: resp.StatusCode,
			Errors:     env.Errors,
		}
	}

	return env.Result, nil
}

func (c *CloudflareClient) discoverTopologyFromDNS(ctx context.Context, zoneID, zoneDomain string) {
	if zoneID == "" {
		return
	}
	recordsPath := "/zones/" + zoneID + "/dns_records?per_page=100"
	records, err := doCFRequest[[]cfDNSRecord](ctx, c, http.MethodGet, recordsPath, nil)
	if err != nil || len(records) == 0 {
		return
	}

	c.mu.RLock()
	prefDom := c.preferredDomain
	curLC := c.lucityOrigin
	c.mu.RUnlock()

	var matchedCFHost string
	var matchedLCTarget string
	var commentLCTarget string

	for _, rec := range records {
		if savedLC := extractCommentLucityDomain(rec.Comment); savedLC != "" {
			if commentLCTarget == "" || isFullLucityServiceDomain(savedLC) {
				commentLCTarget = savedLC
			}
		}

		recType := strings.ToUpper(strings.TrimSpace(rec.Type))
		if recType != "CNAME" {
			continue
		}
		recName := cleanHost(rec.Name)
		recContent := cleanHost(rec.Content)

		if !isLucityManagedDomain(recContent) {
			continue
		}

		if prefDom != "" && recName == prefDom {
			matchedCFHost = recName
			if isFullLucityServiceDomain(recContent) {
				matchedLCTarget = recContent
			}
			break
		}
		if matchedCFHost == "" || recName == "portal."+zoneDomain || recName == zoneDomain {
			matchedCFHost = recName
			if isFullLucityServiceDomain(recContent) {
				matchedLCTarget = recContent
			}
		}
	}

	updated := false
	c.mu.Lock()
	if matchedCFHost != "" {
		if c.preferredDomain == "" {
			c.preferredDomain = matchedCFHost
		}
		if c.cachedZone == "" || c.cachedZone == zoneDomain {
			c.cachedZone = matchedCFHost
		}
		updated = true
	}

	bestLC := curLC
	if !isFullLucityServiceDomain(bestLC) {
		if isFullLucityServiceDomain(commentLCTarget) {
			bestLC = commentLCTarget
		} else if isFullLucityServiceDomain(matchedLCTarget) {
			bestLC = matchedLCTarget
		}
	}

	if isFullLucityServiceDomain(bestLC) && bestLC != c.lucityOrigin {
		c.lucityOrigin = bestLC
		updated = true
		log.Printf("[Cloudflare] ✓ Auto-discovered Lucity Service Domain from DNS: %s", bestLC)
	}
	c.mu.Unlock()

	if updated {
		c.notifyTopology()
	}
}

func (c *CloudflareClient) selectBestZone(ctx context.Context, zones []cfZoneDetails, prefDom string) cfZoneDetails {
	selected := zones[0]
	if prefDom != "" {
		for _, z := range zones {
			zName := strings.TrimSpace(strings.ToLower(z.Name))
			if zName == prefDom || strings.HasSuffix(prefDom, "."+zName) {
				return z
			}
		}
		return selected
	}

	if len(zones) > 1 {
		for _, z := range zones {
			recPath := "/zones/" + z.ID + "/dns_records?per_page=100"
			records, err := doCFRequest[[]cfDNSRecord](ctx, c, http.MethodGet, recPath, nil)
			if err != nil {
				continue
			}
			for _, rec := range records {
				if extractCommentLucityDomain(rec.Comment) != "" || isLucityManagedDomain(cleanHost(rec.Content)) {
					return z
				}
			}
		}
	}
	return selected
}

func (c *CloudflareClient) FetchZoneDomain(parent context.Context) (string, error) {
	if c == nil || c.Token == "" {
		return "", errors.New("cloudflare client not configured (missing token)")
	}

	c.mu.RLock()
	if c.cachedZone != "" && c.ZoneID != "" {
		domain := c.cachedZone
		c.mu.RUnlock()
		return domain, nil
	}
	currentZoneID := c.ZoneID
	prefDom := c.preferredDomain
	c.mu.RUnlock()

	ctx, cancel := context.WithTimeout(parent, defaultZoneDiscoverTimeout)
	defer cancel()

	var zoneDomain string

	if currentZoneID == "" {
		zones, err := doCFRequest[[]cfZoneDetails](ctx, c, http.MethodGet, "/zones?status=active&per_page=50", nil)
		if err != nil {
			var apiErr *cfAPIError
			if errors.As(err, &apiErr) && apiErr.IsInvalidToken() {
				log.Printf("[Cloudflare] Hint: CLOUDFLARE_API_TOKEN (length=%d) was rejected by Cloudflare. Ensure you created a 'User API Token' via the CLOUDFLARE TOKEN button.", len(c.Token))
			}
			return "", fmt.Errorf("auto-discover zones query failed: %w", err)
		}
		if len(zones) == 0 {
			return "", errors.New("no active zones found under this cloudflare api token")
		}

		selected := c.selectBestZone(ctx, zones, prefDom)
		zoneDomain = strings.TrimSpace(strings.ToLower(selected.Name))
		currentZoneID = selected.ID

		c.mu.Lock()
		c.ZoneID = currentZoneID
		if c.cachedZone == "" {
			if prefDom != "" && (prefDom == zoneDomain || strings.HasSuffix(prefDom, "."+zoneDomain)) {
				c.cachedZone = prefDom
			} else {
				c.cachedZone = "portal." + zoneDomain
			}
		}
		c.mu.Unlock()

		log.Printf("[Cloudflare] ✓ Auto-discovered Zone ID: %s for zone: %s (Total Active Zones: %d)",
			currentZoneID, zoneDomain, len(zones))
	} else {
		path := "/zones/" + currentZoneID
		res, err := doCFRequest[cfZoneDetails](ctx, c, http.MethodGet, path, nil)
		if err != nil {
			return "", fmt.Errorf("fetch zone details failed: %w", err)
		}

		zoneDomain = strings.TrimSpace(strings.ToLower(res.Name))
		if zoneDomain != "" {
			c.mu.Lock()
			if c.cachedZone == "" {
				if prefDom != "" && (prefDom == zoneDomain || strings.HasSuffix(prefDom, "."+zoneDomain)) {
					c.cachedZone = prefDom
				} else {
					c.cachedZone = "portal." + zoneDomain
				}
			}
			c.mu.Unlock()
			log.Printf("[Cloudflare] ✓ Resolved Zone Domain for Zone %s: %s", currentZoneID, zoneDomain)
		}
	}

	c.discoverTopologyFromDNS(ctx, currentZoneID, zoneDomain)

	return c.CachedZoneDomain(), nil
}

func (c *CloudflareClient) CachedZoneDomain() string {
	if c == nil {
		return ""
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.preferredDomain != "" {
		return c.preferredDomain
	}
	return c.cachedZone
}

type cfSettingResult struct {
	ID       string `json:"id"`
	Value    any    `json:"value"`
	Editable bool   `json:"editable"`
}

type cfSettingTarget struct {
	Name  string
	Path  string
	Value any
}

func (c *CloudflareClient) ensureSetting(ctx context.Context, target cfSettingTarget) bool {
	cur, err := doCFRequest[cfSettingResult](ctx, c, http.MethodGet, target.Path, nil)
	if err != nil {
		var apiErr *cfAPIError
		if errors.As(err, &apiErr) && (apiErr.IsPermissionOrPlan() || apiErr.StatusCode == http.StatusNotFound) {
			log.Printf("[Cloudflare] Note: %s skipped (plan/permission restriction)", target.Name)
			return false
		}
		log.Printf("[Cloudflare] Warning: Read failed for %s: %v", target.Name, err)
		return false
	}

	if fmt.Sprint(cur.Value) == fmt.Sprint(target.Value) {
		log.Printf("[Cloudflare] ✓ %s: ALREADY OPTIMAL (%v)", target.Name, cur.Value)
		return false
	}

	if !cur.Editable {
		log.Printf("[Cloudflare] Note: %s is locked/read-only on this zone plan (current: %v)", target.Name, cur.Value)
		return false
	}

	payload := map[string]any{"value": target.Value}
	_, err = doCFRequest[cfSettingResult](ctx, c, http.MethodPatch, target.Path, payload)
	if err != nil {
		var apiErr *cfAPIError
		if errors.As(err, &apiErr) && apiErr.IsPermissionOrPlan() {
			log.Printf("[Cloudflare] Note: Patch skipped for %s (insufficient permissions/plan)", target.Name)
			return false
		}
		log.Printf("[Cloudflare] Warning: Patch failed for %s: %v", target.Name, err)
		return false
	}

	log.Printf("[Cloudflare] ✓ %s: ENFORCED -> %v", target.Name, target.Value)
	return true
}

type cfUniversalSSL struct {
	Enabled bool `json:"enabled"`
}

func (c *CloudflareClient) ensureUniversalSSL(ctx context.Context, zoneID string) bool {
	path := "/zones/" + zoneID + "/ssl/universal/settings"
	cur, err := doCFRequest[cfUniversalSSL](ctx, c, http.MethodGet, path, nil)
	if err != nil {
		var apiErr *cfAPIError
		if errors.As(err, &apiErr) && apiErr.IsPermissionOrPlan() {
			log.Println("[Cloudflare] Note: Universal SSL check skipped (missing 'SSL and Certificates' permission)")
			return false
		}
		log.Printf("[Cloudflare] Note: Universal SSL query skipped: %v", err)
		return false
	}

	if cur.Enabled {
		log.Println("[Cloudflare] ✓ Universal Edge SSL Certificates: ALREADY ENABLED")
		return false
	}

	_, err = doCFRequest[cfUniversalSSL](ctx, c, http.MethodPatch, path, cfUniversalSSL{Enabled: true})
	if err != nil {
		log.Printf("[Cloudflare] Warning: Universal SSL enablement unapplied: %v", err)
		return false
	}

	log.Println("[Cloudflare] ✓ Universal Edge SSL Certificates: ENABLED")
	return true
}

type cfZoneDNSSettings struct {
	FlattenAllCNAMEs *bool `json:"flatten_all_cnames,omitempty"`
}

type cfDNSRecord struct {
	ID        string `json:"id"`
	Type      string `json:"type"`
	Name      string `json:"name"`
	Content   string `json:"content"`
	Proxied   bool   `json:"proxied"`
	Proxiable bool   `json:"proxiable"`
	TTL       int    `json:"ttl"`
	Comment   string `json:"comment,omitempty"`
}

// ProvisionLucityDNS creates/updates the CNAME record (`portal.<domain> -> lb.lucity.app`)
// strictly with `Proxied: false` (Grey Cloud / DNS-Only) so Lucity's continuous 2-minute
// `DirectToLoadBalancer` check remains `DNS: Verified / Certificate: Issued` permanently.
func (c *CloudflareClient) ProvisionLucityDNS(ctx context.Context, info *LucityCustomDomainInfo) (string, error) {
	if c == nil || c.Token == "" {
		return "", errors.New("cloudflare client not configured")
	}
	if info == nil || info.Domain == "" {
		return "", errors.New("incomplete lucity custom domain info for DNS provisioning")
	}

	cnameTarget := cleanHost(info.CNAMETarget)
	if cnameTarget == "" || isFullLucityServiceDomain(cnameTarget) {
		cnameTarget = defaultLCCNAMETarget
	}

	zoneID := c.GetZoneID()
	if zoneID == "" {
		if _, err := c.FetchZoneDomain(ctx); err != nil {
			return "", err
		}
		zoneID = c.GetZoneID()
	}
	if zoneID == "" {
		return "", errors.New("missing cloudflare zone ID")
	}

	flattenTarget := cfSettingTarget{
		Name:  "Root CNAME Flattening (Apex Ingress Compatibility)",
		Path:  "/zones/" + zoneID + "/settings/cname_flattening",
		Value: "flatten_at_root",
	}
	c.ensureSetting(ctx, flattenTarget)

	recordsPath := "/zones/" + zoneID + "/dns_records?per_page=100"
	records, err := doCFRequest[[]cfDNSRecord](ctx, c, http.MethodGet, recordsPath, nil)
	if err != nil {
		return "", fmt.Errorf("fetch zone dns records: %w", err)
	}

	verifyHost := info.VerificationHost
	if verifyHost == "" {
		verifyHost = deriveLucityVerifyHost(info.Domain)
	}
	verifyToken := strings.TrimSpace(info.VerificationToken)
	if verifyToken == "" {
		verifyToken = sanitizeExplicitCredential(getEnv("LUCITY_VERIFY_TOKEN", ""))
	}
	if verifyToken != "" && verifyHost != "" {
		c.upsertVerificationTXT(ctx, zoneID, records, verifyHost, verifyToken)
	}

	// Lucity's ingress controller requires DNS-Only (Grey Cloud / Proxied=false) permanently.
	const wantProxied = false

	targetHost := cleanHost(info.Domain)

	var existingCNAME *cfDNSRecord
	var conflictingRecords []cfDNSRecord

	for i := range records {
		rec := &records[i]
		if cleanHost(rec.Name) != targetHost {
			continue
		}
		recType := strings.ToUpper(strings.TrimSpace(rec.Type))
		switch recType {
		case "CNAME":
			existingCNAME = rec
		case "A", "AAAA":
			conflictingRecords = append(conflictingRecords, *rec)
		}
	}

	if existingCNAME == nil && len(conflictingRecords) > 0 && !strings.EqualFold(getEnv("BERMUDA_CF_REPLACE_CONFLICT_DNS", "true"), "false") {
		for _, conflict := range conflictingRecords {
			delPath := fmt.Sprintf("/zones/%s/dns_records/%s", zoneID, conflict.ID)
			if _, delErr := doCFRequest[map[string]any](ctx, c, http.MethodDelete, delPath, nil); delErr == nil {
				log.Printf("[Cloudflare] ✓ Removed conflicting %s record on %s (%s) to allow CNAME binding",
					conflict.Type, conflict.Name, conflict.Content)
			}
		}
	}

	lcOrigin := c.GetLucityOrigin()
	var commentTag string
	if isFullLucityServiceDomain(lcOrigin) {
		candidate := bermudaLCCommentPrefix + lcOrigin
		if len(candidate) <= 95 {
			commentTag = candidate
		}
	}

	if existingCNAME != nil {
		curTarget := cleanHost(existingCNAME.Content)
		curComment := existingCNAME.Comment
		if commentTag == "" {
			commentTag = curComment
		}

		if curTarget == cnameTarget && existingCNAME.Proxied == wantProxied && (commentTag == "" || curComment == commentTag) {
			log.Printf("[Cloudflare] ✓ Lucity CNAME Record (%s -> %s, DNS-Only Grey Cloud): ALREADY SYNCED",
				targetHost, cnameTarget)
			return existingCNAME.ID, nil
		}

		patchPath := fmt.Sprintf("/zones/%s/dns_records/%s", zoneID, existingCNAME.ID)
		payload := map[string]any{
			"type":    "CNAME",
			"name":    targetHost,
			"content": cnameTarget,
			"proxied": wantProxied,
			"ttl":     1,
		}
		if commentTag != "" {
			payload["comment"] = commentTag
		}

		updated, patchErr := doCFRequest[cfDNSRecord](ctx, c, http.MethodPatch, patchPath, payload)
		if patchErr != nil && commentTag != "" {
			delete(payload, "comment")
			updated, patchErr = doCFRequest[cfDNSRecord](ctx, c, http.MethodPatch, patchPath, payload)
		}
		if patchErr != nil {
			return existingCNAME.ID, fmt.Errorf("update lucity cname record: %w", patchErr)
		}

		log.Printf("[Cloudflare] ✓ Synced Lucity CNAME Record: %s -> %s (Proxied=%v · DNS-Only Grey Cloud)",
			targetHost, cnameTarget, updated.Proxied)
		return updated.ID, nil
	}

	postPath := fmt.Sprintf("/zones/%s/dns_records", zoneID)
	payload := map[string]any{
		"type":    "CNAME",
		"name":    targetHost,
		"content": cnameTarget,
		"proxied": wantProxied,
		"ttl":     1,
	}
	if commentTag != "" {
		payload["comment"] = commentTag
	}

	created, postErr := doCFRequest[cfDNSRecord](ctx, c, http.MethodPost, postPath, payload)
	if postErr != nil && commentTag != "" {
		delete(payload, "comment")
		created, postErr = doCFRequest[cfDNSRecord](ctx, c, http.MethodPost, postPath, payload)
	}
	if postErr != nil {
		return "", fmt.Errorf("create lucity cname record: %w", postErr)
	}

	log.Printf("[Cloudflare] ✓ Auto-Created Lucity CNAME Record: %s -> %s (Proxied=%v · DNS-Only Grey Cloud)",
		targetHost, cnameTarget, created.Proxied)
	return created.ID, nil
}

func (c *CloudflareClient) upsertVerificationTXT(ctx context.Context, zoneID string, records []cfDNSRecord, verifyHost, verifyToken string) {
	cleanVerifyHost := cleanHost(verifyHost)
	cleanToken := strings.Trim(strings.TrimSpace(verifyToken), "\"")
	if cleanVerifyHost == "" || cleanToken == "" {
		return
	}

	var existingTXT *cfDNSRecord
	for i := range records {
		rec := &records[i]
		if strings.ToUpper(strings.TrimSpace(rec.Type)) != "TXT" {
			continue
		}
		if cleanHost(rec.Name) != cleanVerifyHost {
			continue
		}
		curVal := strings.Trim(strings.TrimSpace(rec.Content), "\"")
		if curVal == cleanToken {
			log.Printf("[Cloudflare] ✓ Lucity Ownership TXT Record (%s): ALREADY VERIFIED", cleanVerifyHost)
			return
		}
		existingTXT = rec
	}

	payload := map[string]any{
		"type":    "TXT",
		"name":    cleanVerifyHost,
		"content": cleanToken,
		"ttl":     1,
	}

	if existingTXT != nil {
		patchPath := fmt.Sprintf("/zones/%s/dns_records/%s", zoneID, existingTXT.ID)
		if _, err := doCFRequest[cfDNSRecord](ctx, c, http.MethodPatch, patchPath, payload); err == nil {
			log.Printf("[Cloudflare] ✓ Updated Lucity Ownership TXT Record: %s", cleanVerifyHost)
			return
		}
	}

	postPath := fmt.Sprintf("/zones/%s/dns_records", zoneID)
	if _, err := doCFRequest[cfDNSRecord](ctx, c, http.MethodPost, postPath, payload); err != nil {
		log.Printf("[Cloudflare] Note: Could not create TXT record %s: %v", cleanVerifyHost, err)
		return
	}
	log.Printf("[Cloudflare] ✓ Auto-Created Lucity Ownership TXT Record: %s", cleanVerifyHost)
}

func (c *CloudflareClient) ensureDNSConfiguration(ctx context.Context, zoneID, zoneDomain string) bool {
	modified := false

	flattenTarget := cfSettingTarget{
		Name:  "Root CNAME Flattening (Apex Ingress Compatibility)",
		Path:  "/zones/" + zoneID + "/settings/cname_flattening",
		Value: "flatten_at_root",
	}
	if c.ensureSetting(ctx, flattenTarget) {
		modified = true
	}

	dnsSettingsPath := "/zones/" + zoneID + "/dns_settings"
	if curDNS, err := doCFRequest[cfZoneDNSSettings](ctx, c, http.MethodGet, dnsSettingsPath, nil); err == nil {
		if curDNS.FlattenAllCNAMEs != nil && *curDNS.FlattenAllCNAMEs {
			log.Println("[Cloudflare] ✓ Zone DNS Settings: CNAME Flattening Active")
		}
	}

	recordsPath := "/zones/" + zoneID + "/dns_records?per_page=100"
	records, err := doCFRequest[[]cfDNSRecord](ctx, c, http.MethodGet, recordsPath, nil)
	if err != nil {
		var apiErr *cfAPIError
		if errors.As(err, &apiErr) && apiErr.IsPermissionOrPlan() {
			log.Println("[Cloudflare] Note: DNS record verification skipped (missing 'DNS: Edit' permission)")
			return modified
		}
		log.Printf("[Cloudflare] Note: DNS records list skipped: %v", err)
		return modified
	}

	c.mu.RLock()
	prefDom := c.preferredDomain
	lcOrigin := c.lucityOrigin
	c.mu.RUnlock()

	if !isFullLucityServiceDomain(lcOrigin) {
		envLC, _ := resolveInfrastructureDomains()
		if isFullLucityServiceDomain(envLC) {
			lcOrigin = envLC
		}
	}

	topologyChanged := false

	for _, rec := range records {
		if savedLC := extractCommentLucityDomain(rec.Comment); savedLC != "" && !isFullLucityServiceDomain(lcOrigin) {
			lcOrigin = savedLC
			c.SetLucityOrigin(savedLC)
			topologyChanged = true
		}

		recType := strings.ToUpper(strings.TrimSpace(rec.Type))
		if recType != "CNAME" {
			continue
		}
		recName := cleanHost(rec.Name)
		recContent := cleanHost(rec.Content)

		isTargetHost := (recName == zoneDomain) || (prefDom != "" && recName == prefDom)
		isLucityTarget := isLucityManagedDomain(recContent)

		if isLucityTarget {
			if isFullLucityServiceDomain(recContent) && !isFullLucityServiceDomain(lcOrigin) {
				lcOrigin = recContent
				c.SetLucityOrigin(recContent)
				topologyChanged = true
			}
			if prefDom == "" && recName != "" {
				prefDom = recName
				c.SetPreferredDomain(recName)
				topologyChanged = true
			}
		}

		wantComment := rec.Comment
		if isLucityTarget && isFullLucityServiceDomain(lcOrigin) {
			expectedTag := bermudaLCCommentPrefix + lcOrigin
			if extractCommentLucityDomain(rec.Comment) != lcOrigin && len(expectedTag) <= 95 {
				wantComment = expectedTag
			}
		}

		// Ensure any CNAME pointing to Lucity stays on Grey Cloud (Proxied=false)
		needsGreyCloud := (isTargetHost || isLucityTarget) && rec.Proxied
		needsCommentPatch := wantComment != rec.Comment

		if needsGreyCloud || needsCommentPatch {
			patchPath := fmt.Sprintf("/zones/%s/dns_records/%s", zoneID, rec.ID)
			patchPayload := map[string]any{
				"type":    rec.Type,
				"name":    rec.Name,
				"content": rec.Content,
				"proxied": false,
				"ttl":     1,
			}
			if needsCommentPatch {
				patchPayload["comment"] = wantComment
			}
			if _, patchErr := doCFRequest[cfDNSRecord](ctx, c, http.MethodPatch, patchPath, patchPayload); patchErr == nil {
				if needsGreyCloud {
					log.Printf("[Cloudflare] ✓ DNS Record %s (%s -> %s): ENFORCED DNS-ONLY GREY CLOUD (Proxied=false for Lucity TLS)",
						rec.Name, rec.Type, rec.Content)
					modified = true
				}
			} else if needsGreyCloud && needsCommentPatch {
				delete(patchPayload, "comment")
				if _, retryErr := doCFRequest[cfDNSRecord](ctx, c, http.MethodPatch, patchPath, patchPayload); retryErr == nil {
					log.Printf("[Cloudflare] ✓ DNS Record %s (%s -> %s): ENFORCED DNS-ONLY GREY CLOUD (Proxied=false for Lucity TLS)",
						rec.Name, rec.Type, rec.Content)
					modified = true
				}
			}
		} else if (isTargetHost || isLucityTarget) && !rec.Proxied {
			log.Printf("[Cloudflare] ✓ DNS Record %s (%s -> %s): DNS-ONLY GREY CLOUD ACTIVE (Proxied=false)",
				rec.Name, rec.Type, rec.Content)
		}
	}

	if topologyChanged {
		c.notifyTopology()
	}

	return modified
}

func (c *CloudflareClient) Tune(parent context.Context) {
	ctx, cancel := context.WithTimeout(parent, defaultEdgeTuneTimeout)
	defer cancel()

	domainName, err := c.FetchZoneDomain(ctx)
	if err != nil {
		log.Printf("[Cloudflare] Error: Could not resolve zone details: %v. Aborting DNS sync.", err)
		return
	}

	zoneID := c.GetZoneID()
	log.Printf("[Cloudflare] Verifying DNS-Only (Grey Cloud) Configuration for Zone %s (Domain: %s)...", zoneID, domainName)

	if ctx.Err() == nil {
		c.ensureUniversalSSL(ctx, zoneID)
	}
	if ctx.Err() == nil {
		c.ensureDNSConfiguration(ctx, zoneID, domainName)
	}

	log.Printf("[Cloudflare] DNS-Only Configuration verified for Zone %s (Domain: %s)", zoneID, c.CachedZoneDomain())
}
