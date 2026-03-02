package main

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var (
	baseStyle = lipgloss.NewStyle().
			BorderStyle(lipgloss.NormalBorder()).
			BorderForeground(lipgloss.Color("240"))

	statusStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("241")).
			Padding(0, 1)

	filterActiveStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("205"))

	sortIndicator = map[bool]string{true: " ▲", false: " ▼"}
)

type model struct {
	table      table.Model
	allRecords []*IPRecord         // full dataset
	ipIndex    map[string]*IPRecord // IP -> record for fast lookup
	sortState  SortState
	filterMode bool
	filterText textinput.Model
	width      int
	height     int

	// Whois loading state
	whoisLoading bool
	whoisDone    int
	whoisTotal   int
}

func newModel(records []*IPRecord) model {
	ti := textinput.New()
	ti.Placeholder = "filter..."
	ti.CharLimit = 100

	idx := make(map[string]*IPRecord, len(records))
	for _, r := range records {
		idx[r.IP] = r
	}

	m := model{
		allRecords:   records,
		ipIndex:      idx,
		sortState:    SortState{Column: ColCount, Asc: false},
		filterText:   ti,
		whoisLoading: true,
	}

	m.rebuildTable()
	return m
}

func (m *model) rebuildTable() {
	// Apply filter
	visible := filterRecords(m.allRecords, m.filterText.Value())

	// Apply sort
	sortRecords(visible, m.sortState)

	// Build column headers with sort indicator
	headers := make([]string, NumColumns)
	for i, name := range columnNames {
		if i == m.sortState.Column {
			headers[i] = name + sortIndicator[m.sortState.Asc]
		} else {
			headers[i] = name
		}
	}

	// Calculate column widths based on terminal width
	// bubbles/table uses 1 char padding on each side of each column = 2*NumColumns
	// plus the base style border adds 2
	available := m.width - (2*NumColumns + 2)
	if available < 80 {
		available = 80
	}

	// Proportional column widths
	colWidths := distributeWidths(available)

	columns := make([]table.Column, NumColumns)
	for i := 0; i < NumColumns; i++ {
		columns[i] = table.Column{Title: headers[i], Width: colWidths[i]}
	}

	rows := make([]table.Row, len(visible))
	for i, rec := range visible {
		rows[i] = rowFromRecord(rec)
	}

	tableHeight := m.height - 6 // header + status + filter line + borders
	if tableHeight < 5 {
		tableHeight = 5
	}

	t := table.New(
		table.WithColumns(columns),
		table.WithRows(rows),
		table.WithFocused(true),
		table.WithHeight(tableHeight),
	)

	s := table.DefaultStyles()
	s.Header = s.Header.
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("240")).
		BorderBottom(true).
		Bold(true)
	s.Selected = s.Selected.
		Foreground(lipgloss.Color("229")).
		Background(lipgloss.Color("57")).
		Bold(false)
	t.SetStyles(s)

	m.table = t
}

func distributeWidths(total int) [NumColumns]int {
	// Count | IP | Process(es) | Org | Net | Location
	fixedCount := 6
	fixedIP := 17
	remaining := total - fixedCount - fixedIP
	if remaining < 40 {
		remaining = 40
	}

	procW := remaining * 20 / 100
	orgW := remaining * 35 / 100
	netW := remaining * 20 / 100
	locW := remaining - procW - orgW - netW // absorb rounding remainder

	return [NumColumns]int{
		fixedCount,
		fixedIP,
		procW,
		orgW,
		netW,
		locW,
	}
}

func (m model) Init() tea.Cmd {
	return nil
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.rebuildTable()
		return m, nil

	case whoisBatchResults:
		for _, r := range msg.Results {
			if rec, ok := m.ipIndex[r.IP]; ok {
				applyWhoisToRecord(rec, r.Entry)
			}
		}
		m.whoisLoading = false
		m.whoisDone = len(msg.Results)
		m.whoisTotal = msg.Total
		m.rebuildTable()
		return m, nil

	case WhoisBatchDone:
		m.whoisLoading = false
		m.rebuildTable()
		return m, nil

	case tea.KeyMsg:
		if m.filterMode {
			return m.handleFilterKey(msg)
		}
		return m.handleNormalKey(msg)
	}

	return m, nil
}

func (m model) handleFilterKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.filterMode = false
		m.filterText.Blur()
		m.filterText.SetValue("")
		m.rebuildTable()
		return m, nil
	case "enter":
		m.filterMode = false
		m.filterText.Blur()
		m.rebuildTable()
		return m, nil
	default:
		var cmd tea.Cmd
		m.filterText, cmd = m.filterText.Update(msg)
		m.rebuildTable()
		return m, cmd
	}
}

func (m model) handleNormalKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "ctrl+c":
		return m, tea.Quit
	case "/":
		m.filterMode = true
		m.filterText.Focus()
		return m, textinput.Blink
	case "1", "2", "3", "4", "5", "6":
		col := int(msg.String()[0] - '1')
		if col == m.sortState.Column {
			m.sortState.Asc = !m.sortState.Asc
		} else {
			m.sortState.Column = col
			m.sortState.Asc = true
		}
		m.rebuildTable()
		return m, nil
	default:
		var cmd tea.Cmd
		m.table, cmd = m.table.Update(msg)
		return m, cmd
	}
}

func (m model) View() string {
	var b strings.Builder

	// Table
	b.WriteString(baseStyle.Render(m.table.View()))
	b.WriteString("\n")

	// Status line
	var parts []string

	if m.whoisLoading {
		parts = append(parts, fmt.Sprintf("Loading whois... (%d/%d)", m.whoisDone, m.whoisTotal))
	}

	if m.filterMode {
		parts = append(parts, filterActiveStyle.Render("Filter: ")+m.filterText.View())
	} else if m.filterText.Value() != "" {
		filtered := filterRecords(m.allRecords, m.filterText.Value())
		parts = append(parts, filterActiveStyle.Render(
			fmt.Sprintf("Filter: %q (%d/%d)", m.filterText.Value(), len(filtered), len(m.allRecords)),
		))
	}

	parts = append(parts, statusStyle.Render(
		fmt.Sprintf("%d IPs | ↑↓ navigate | 1-6 sort | / filter | q quit", len(m.allRecords)),
	))

	b.WriteString(strings.Join(parts, "  "))

	return b.String()
}
