package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

const (
	cacheTTL     = 7 * 24 * time.Hour
	maxConcurrent = 10
)

// WhoisEntry is a cached whois result for a single IP.
type WhoisEntry struct {
	Org      string `json:"org"`
	Net      string `json:"net"`
	City     string `json:"city"`
	Country  string `json:"country"`
	Source   string `json:"source"` // "whois", "nslookup", "ipinfo", "local"
	Info     string `json:"info"`   // combined info string for private IPs
	Fetched  string `json:"fetched"`
}

type WhoisCache map[string]WhoisEntry

func loadWhoisCache(path string) WhoisCache {
	cache := make(WhoisCache)
	data, err := os.ReadFile(path)
	if err != nil {
		return cache
	}
	_ = json.Unmarshal(data, &cache)
	return cache
}

func saveWhoisCache(path string, cache WhoisCache) error {
	data, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func isCacheValid(entry WhoisEntry) bool {
	t, err := time.Parse(time.RFC3339, entry.Fetched)
	if err != nil {
		return false
	}
	return time.Since(t) < cacheTTL
}

// WhoisResult is a bubbletea message carrying a completed whois lookup.
type WhoisResult struct {
	IP    string
	Entry WhoisEntry
}

// WhoisBatchDone signals all lookups are complete.
type WhoisBatchDone struct{}

// WhoisProgress reports how many lookups are done.
type WhoisProgress struct {
	Done  int
	Total int
}

// startWhoisLookups kicks off background whois lookups for all non-cached IPs.
// It returns a tea.Cmd that sends WhoisResult messages as they complete.
func startWhoisLookups(records []*IPRecord, cache WhoisCache, cachePath string) tea.Cmd {
	// Determine which IPs need lookup
	var needLookup []*IPRecord
	for _, rec := range records {
		if rec.IsPrivate {
			// Store private IP info in cache
			entry := WhoisEntry{
				Source:  "local",
				Info:    rec.PrivateInfo,
				Fetched: time.Now().Format(time.RFC3339),
			}
			cache[rec.IP] = entry
			rec.Source = "local"
			rec.Org = rec.PrivateInfo
			continue
		}
		if existing, ok := cache[rec.IP]; ok && isCacheValid(existing) {
			applyWhoisToRecord(rec, existing)
			continue
		}
		needLookup = append(needLookup, rec)
	}

	if len(needLookup) == 0 {
		_ = saveWhoisCache(cachePath, cache)
		return func() tea.Msg { return WhoisBatchDone{} }
	}

	return func() tea.Msg {
		sem := make(chan struct{}, maxConcurrent)
		var mu sync.Mutex
		done := 0
		total := len(needLookup)
		results := make(chan WhoisResult, total)

		var wg sync.WaitGroup
		for _, rec := range needLookup {
			wg.Add(1)
			go func(ip string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				entry := lookupIP(ip)
				mu.Lock()
				cache[ip] = entry
				done++
				mu.Unlock()

				results <- WhoisResult{IP: ip, Entry: entry}
			}(rec.IP)
		}

		// Wait for all to finish, then save cache
		go func() {
			wg.Wait()
			mu.Lock()
			_ = saveWhoisCache(cachePath, cache)
			mu.Unlock()
			close(results)
		}()

		// Collect all results and return them
		var allResults []WhoisResult
		for r := range results {
			allResults = append(allResults, r)
		}

		return whoisBatchResults{Results: allResults, Total: total}
	}
}

type whoisBatchResults struct {
	Results []WhoisResult
	Total   int
}

func applyWhoisToRecord(rec *IPRecord, entry WhoisEntry) {
	rec.Source = entry.Source
	rec.Net = entry.Net

	switch entry.Source {
	case "local":
		rec.Org = entry.Info
	case "whois":
		rec.Org = entry.Org
		if entry.City != "" && entry.Country != "" {
			rec.Location = entry.City + ", " + entry.Country
		} else if entry.Country != "" {
			rec.Location = entry.Country
		}
	case "nslookup":
		rec.Org = entry.Info
	case "ipinfo":
		rec.Org = entry.Info
	case "unknown":
		rec.Org = "—"
	default:
		rec.Org = entry.Org
	}
}

func lookupIP(ip string) WhoisEntry {
	entry := WhoisEntry{Fetched: time.Now().Format(time.RFC3339)}

	// Try whois first
	if tryWhois(ip, &entry) {
		return entry
	}

	// Try nslookup
	if tryNslookup(ip, &entry) {
		return entry
	}

	// Try ipinfo.io
	if tryIPInfo(ip, &entry) {
		return entry
	}

	entry.Source = "unknown"
	entry.Info = "—"
	return entry
}

var (
	reOrgName = regexp.MustCompile(`(?im)^(OrgName|org-name)\s*:\s*(.+)$`)
	reNetName = regexp.MustCompile(`(?im)^(NetName|netname)\s*:\s*(.+)$`)
	reCity    = regexp.MustCompile(`(?im)^City\s*:\s*(.+)$`)
	reCountry = regexp.MustCompile(`(?im)^Country\s*:\s*(.+)$`)
	reDescr   = regexp.MustCompile(`(?im)^descr\s*:\s*(.+)$`)
)

func tryWhois(ip string, entry *WhoisEntry) bool {
	out, err := exec.Command("timeout", "10", "whois", ip).Output()
	if err != nil {
		return false
	}
	output := string(out)

	orgname := extractField(reOrgName, output)
	netname := extractField(reNetName, output)
	city := extractField(reCity, output)
	country := extractField(reCountry, output)
	descr := extractField(reDescr, output)

	// Build detail string same way as list_IPs.sh
	detail := ""
	if orgname != "" {
		detail = orgname
	} else if descr != "" {
		detail = descr
	}
	if netname != "" {
		if detail != "" {
			detail += ", net:" + netname
		} else {
			detail = "net:" + netname
		}
	}

	if detail == "" {
		return false
	}

	entry.Source = "whois"
	entry.Org = orgname
	if entry.Org == "" {
		entry.Org = descr
	}
	entry.Net = netname
	entry.City = strings.TrimSpace(city)
	entry.Country = strings.TrimSpace(country)
	return true
}

func extractField(re *regexp.Regexp, text string) string {
	m := re.FindStringSubmatch(text)
	if m == nil {
		return ""
	}
	// Last capture group has the value
	return strings.TrimSpace(m[len(m)-1])
}

func tryNslookup(ip string, entry *WhoisEntry) bool {
	out, err := exec.Command("timeout", "10", "nslookup", ip).Output()
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(out), "\n") {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "name") && strings.Contains(line, "=") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				name := strings.TrimSpace(parts[1])
				name = strings.TrimSuffix(name, ".")
				if name != "" {
					entry.Source = "nslookup"
					entry.Info = name
					return true
				}
			}
		}
		// Also handle "name = value" format from some nslookup outputs
		if strings.Contains(lower, "name") {
			fields := strings.Fields(line)
			if len(fields) > 0 {
				name := strings.TrimSuffix(fields[len(fields)-1], ".")
				if name != "" && name != "name" {
					entry.Source = "nslookup"
					entry.Info = name
					return true
				}
			}
		}
	}
	return false
}

func tryIPInfo(ip string, entry *WhoisEntry) bool {
	out, err := exec.Command("timeout", "10", "curl", "-s", fmt.Sprintf("https://ipinfo.io/%s", ip)).Output()
	if err != nil {
		return false
	}

	var data map[string]interface{}
	if err := json.Unmarshal(out, &data); err != nil {
		return false
	}

	org, _ := data["org"].(string)
	hostname, _ := data["hostname"].(string)

	if hostname != "" {
		if org != "" {
			entry.Info = hostname + " (" + org + ")"
		} else {
			entry.Info = hostname
		}
		entry.Source = "ipinfo"
		entry.Org = org
		return true
	}
	if org != "" {
		entry.Info = org
		entry.Source = "ipinfo"
		entry.Org = org
		return true
	}

	return false
}
