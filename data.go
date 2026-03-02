package main

import (
	"encoding/csv"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
)

// IPRecord holds aggregated data for a single remote IP.
type IPRecord struct {
	IP          string
	Count       int
	Processes   []string
	FirstSeen   time.Time
	LastSeen    time.Time
	IsPrivate   bool
	PrivateInfo string // "this machine (hostname)", "default gateway", "private IP", etc.

	// Filled in by whois lookup
	Org      string
	Net      string
	Location string
	Source   string // "whois", "nslookup", "ipinfo", "local", "unknown"
}

func loadCSV(path string) ([]*IPRecord, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open csv: %w", err)
	}
	defer f.Close()

	reader := csv.NewReader(f)
	reader.LazyQuotes = true
	reader.FieldsPerRecord = -1 // allow variable fields

	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("read csv: %w", err)
	}

	if len(records) < 2 {
		return nil, fmt.Errorf("csv has no data rows")
	}

	myIPs := getLocalIPs()
	defaultGW := getDefaultGateway()

	// Aggregate by remote_ip
	type agg struct {
		count     int
		procs     map[string]bool
		firstSeen time.Time
		lastSeen  time.Time
	}
	ipMap := make(map[string]*agg)

	for _, row := range records[1:] { // skip header
		if len(row) < 5 {
			continue
		}
		ts := parseTimestamp(row[0])
		proc := row[1]
		ip := row[4]

		if ip == "" {
			continue
		}

		a, ok := ipMap[ip]
		if !ok {
			a = &agg{procs: make(map[string]bool), firstSeen: ts, lastSeen: ts}
			ipMap[ip] = a
		}
		a.count++
		a.procs[proc] = true
		if ts.Before(a.firstSeen) {
			a.firstSeen = ts
		}
		if ts.After(a.lastSeen) {
			a.lastSeen = ts
		}
	}

	// Convert to sorted slice (by count descending)
	result := make([]*IPRecord, 0, len(ipMap))
	for ip, a := range ipMap {
		procs := make([]string, 0, len(a.procs))
		for p := range a.procs {
			procs = append(procs, p)
		}
		sort.Strings(procs)

		rec := &IPRecord{
			IP:        ip,
			Count:     a.count,
			Processes: procs,
			FirstSeen: a.firstSeen,
			LastSeen:  a.lastSeen,
			IsPrivate: isPrivateIP(ip),
			Source:    "",
		}

		if rec.IsPrivate {
			rec.Source = "local"
			rec.PrivateInfo = resolvePrivateIP(ip, myIPs, defaultGW)
		}

		result = append(result, rec)
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Count > result[j].Count
	})

	return result, nil
}

func parseTimestamp(s string) time.Time {
	// Format 1: "02.03.2026 09:02:19.503:1517" (DD.MM.YYYY HH:MM:SS.mmm:sequence)
	if len(s) > 10 && s[2] == '.' && s[5] == '.' {
		// Strip the :sequence suffix after milliseconds
		tsPart := s
		// Find the last colon that separates ms from sequence number
		if idx := strings.LastIndex(s, ":"); idx > 19 {
			tsPart = s[:idx]
		}
		t, err := time.Parse("02.01.2006 15:04:05.000", tsPart)
		if err == nil {
			return t
		}
		// Try without milliseconds
		if dotIdx := strings.LastIndex(tsPart, "."); dotIdx > 10 {
			t, err = time.Parse("02.01.2006 15:04:05", tsPart[:dotIdx])
			if err == nil {
				return t
			}
		}
	}

	// Format 2: Unix epoch "1772446915.994"
	parts := strings.SplitN(s, ".", 2)
	sec, err := strconv.ParseInt(parts[0], 10, 64)
	if err == nil {
		var nsec int64
		if len(parts) == 2 {
			// Pad or truncate to nanoseconds
			frac := parts[1]
			for len(frac) < 9 {
				frac += "0"
			}
			nsec, _ = strconv.ParseInt(frac[:9], 10, 64)
		}
		return time.Unix(sec, nsec)
	}

	return time.Time{}
}

func isPrivateIP(ipStr string) bool {
	// Handle IPv6 loopback
	if ipStr == "::1" {
		return true
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	// IPv4 private ranges
	privateRanges := []struct {
		network string
		mask    string
	}{
		{"10.0.0.0", "255.0.0.0"},
		{"172.16.0.0", "255.240.0.0"},
		{"192.168.0.0", "255.255.0.0"},
		{"127.0.0.0", "255.0.0.0"},
	}

	for _, r := range privateRanges {
		network := net.ParseIP(r.network)
		mask := net.IPMask(net.ParseIP(r.mask).To4())
		if network != nil && mask != nil {
			n := &net.IPNet{IP: network, Mask: mask}
			if n.Contains(ip) {
				return true
			}
		}
	}

	// IPv6 link-local (fe80::/10) and unique local (fc00::/7)
	if ip.To4() == nil {
		if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsLoopback() {
			return true
		}
		// fc00::/7 — unique local
		if len(ip) >= 1 && (ip[0]&0xfe) == 0xfc {
			return true
		}
	}

	return false
}

func getLocalIPs() map[string]bool {
	result := make(map[string]bool)
	out, err := exec.Command("hostname", "-I").Output()
	if err == nil {
		for _, ip := range strings.Fields(string(out)) {
			result[strings.TrimSpace(ip)] = true
		}
	}
	return result
}

func getDefaultGateway() string {
	out, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil {
		return ""
	}
	fields := strings.Fields(string(out))
	for i, f := range fields {
		if f == "via" && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	return ""
}

func resolvePrivateIP(ip string, myIPs map[string]bool, defaultGW string) string {
	if ip == "127.0.0.1" || ip == "127.0.0.53" || ip == "::1" {
		hostname, _ := os.Hostname()
		if hostname != "" {
			return "loopback (" + hostname + ")"
		}
		return "loopback"
	}
	if myIPs[ip] {
		hostname, _ := os.Hostname()
		if hostname != "" {
			return "this machine (" + hostname + ")"
		}
		return "this machine"
	}
	if ip == defaultGW {
		return "default gateway"
	}

	// Try reverse DNS
	out, err := exec.Command("getent", "hosts", ip).Output()
	if err == nil {
		fields := strings.Fields(string(out))
		if len(fields) >= 2 {
			return fields[1]
		}
	}

	return "private IP"
}
