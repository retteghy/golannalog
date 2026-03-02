package main

import (
	"fmt"
	"os"
	"path/filepath"

	tea "github.com/charmbracelet/bubbletea"
)

func main() {
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	baseDir := filepath.Join(home, ".golannalog")
	csvPath := filepath.Join(baseDir, "audit_connections.csv")
	cachePath := filepath.Join(baseDir, "whois_cache.json")

	records, err := loadCSV(csvPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading CSV: %v\n", err)
		os.Exit(1)
	}

	if len(records) == 0 {
		fmt.Fprintln(os.Stderr, "No connection records found.")
		os.Exit(0)
	}

	cache := loadWhoisCache(cachePath)

	m := newModel(records)
	m.whoisTotal = countPublicIPs(records, cache)

	whoisCmd := startWhoisLookups(records, cache, cachePath)

	p := tea.NewProgram(
		initModel{inner: m, whoisCmd: whoisCmd},
		tea.WithAltScreen(),
	)

	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func countPublicIPs(records []*IPRecord, cache WhoisCache) int {
	count := 0
	for _, r := range records {
		if r.IsPrivate {
			continue
		}
		if existing, ok := cache[r.IP]; ok && isCacheValid(existing) {
			continue
		}
		count++
	}
	return count
}

// initModel wraps the real model to fire the whois command on Init.
type initModel struct {
	inner    model
	whoisCmd tea.Cmd
}

func (im initModel) Init() tea.Cmd {
	return im.whoisCmd
}

func (im initModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	m, cmd := im.inner.Update(msg)
	im.inner = m.(model)
	return im, cmd
}

func (im initModel) View() string {
	return im.inner.View()
}
