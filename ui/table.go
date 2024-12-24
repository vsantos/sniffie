package ui

import (
	"go-udp-study/parser"
	"strconv"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

func SetTable(table *tview.Table) {
	setTableHeaders([]string{"TRACK ID", "SRC", "DST", "FQDN", "PROTO", "ANSWERS", "DURATION (MS)"}, table)
}

func setTableHeaders(headers []string, table *tview.Table) {
	for i, header := range headers {
		table.SetCell(0, i,
			tview.NewTableCell(header).
				SetTextColor(tcell.ColorWhite).
				SetAlign(tview.AlignCenter))
	}

	// setContent(table)

}

func setContent(table *tview.Table) {

	f := len(parser.DNSRequestQueue)

	table.SetCell(0, 8,
		tview.NewTableCell(strconv.Itoa(f)).
			SetTextColor(tcell.ColorWhite).
			SetAlign(tview.AlignCenter))
}
