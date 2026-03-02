package main

import (
	"fmt"
	"sort"
	"strings"
)

// Column indices
const (
	ColCount    = 0
	ColIP       = 1
	ColProcess  = 2
	ColOrg      = 3
	ColNet      = 4
	ColLocation = 5
	NumColumns  = 6
)

var columnNames = [NumColumns]string{
	"Count", "IP", "Process(es)", "Org", "Net", "Location",
}

// SortState tracks the current sort column and direction.
type SortState struct {
	Column int
	Asc    bool
}

// rowFromRecord converts an IPRecord to a string slice for table display.
func rowFromRecord(rec *IPRecord) []string {
	procs := strings.Join(rec.Processes, ", ")

	org := rec.Org
	if rec.IsPrivate && rec.PrivateInfo != "" {
		org = rec.PrivateInfo
	}

	location := rec.Location
	if rec.IsPrivate {
		location = ""
	}

	netName := rec.Net
	if rec.IsPrivate {
		netName = ""
	}

	return []string{
		fmt.Sprintf("%d", rec.Count),
		rec.IP,
		procs,
		org,
		netName,
		location,
	}
}

// sortRecords sorts records in place based on the sort state.
func sortRecords(records []*IPRecord, st SortState) {
	sort.SliceStable(records, func(i, j int) bool {
		var less bool
		switch st.Column {
		case ColCount:
			less = records[i].Count < records[j].Count
		case ColIP:
			less = records[i].IP < records[j].IP
		case ColProcess:
			pi := strings.Join(records[i].Processes, ", ")
			pj := strings.Join(records[j].Processes, ", ")
			less = pi < pj
		case ColOrg:
			oi := records[i].Org
			if records[i].IsPrivate {
				oi = records[i].PrivateInfo
			}
			oj := records[j].Org
			if records[j].IsPrivate {
				oj = records[j].PrivateInfo
			}
			less = strings.ToLower(oi) < strings.ToLower(oj)
		case ColNet:
			less = strings.ToLower(records[i].Net) < strings.ToLower(records[j].Net)
		case ColLocation:
			less = strings.ToLower(records[i].Location) < strings.ToLower(records[j].Location)
		default:
			less = records[i].Count < records[j].Count
		}
		if !st.Asc {
			less = !less
		}
		return less
	})
}

// filterRecords returns records where any column value contains the filter string.
func filterRecords(records []*IPRecord, filter string) []*IPRecord {
	if filter == "" {
		return records
	}
	lower := strings.ToLower(filter)
	var result []*IPRecord
	for _, rec := range records {
		row := rowFromRecord(rec)
		for _, cell := range row {
			if strings.Contains(strings.ToLower(cell), lower) {
				result = append(result, rec)
				break
			}
		}
	}
	return result
}
