package ui

import (
	"fmt"
	"sniffie/parser"
	"strconv"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

const refreshInterval = 500 * time.Millisecond

// SetTable will draw the default sniff table to screen
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

// UpdateTime will update screen's tatble
func UpdateTime(t TUI) {
	for {
		time.Sleep(refreshInterval)
		// t.Table.SetCell(0, 9,
		// 	tview.NewTableCell(RandStringBytes(5)).
		// 		SetTextColor(tcell.ColorWhite).
		// 		SetAlign(tview.AlignCenter))

		stRow := 1
		for _, queue := range parser.DNSRequestQueue {
			// TRACK ID
			t.Table.SetCell(stRow, 0,
				tview.NewTableCell(queue.TrackID).
					SetTextColor(tcell.ColorWhite).
					SetAlign(tview.AlignCenter))

			// SRC
			src := fmt.Sprintf("%s (%s)", queue.Packages.Client.Metadata.Pod, queue.Packages.Client.Payload.SrcIP.String())
			t.Table.SetCell(stRow, 1,
				tview.NewTableCell(src).
					SetTextColor(tcell.ColorWhite).
					SetAlign(tview.AlignCenter))

			// DST
			dst := fmt.Sprintf("%s (%s)", queue.Packages.Server.Metadata.Pod, queue.Packages.Client.Payload.DstIP.String())
			t.Table.SetCell(stRow, 2,
				tview.NewTableCell(dst).
					SetTextColor(tcell.ColorWhite).
					SetAlign(tview.AlignCenter))

			// FQDN
			t.Table.SetCell(stRow, 3,
				tview.NewTableCell(fmt.Sprint(queue.Packages.Client.Payload.Questions[0].Name)).
					SetTextColor(tcell.ColorWhite).
					SetAlign(tview.AlignCenter))

			// PROTO
			t.Table.SetCell(stRow, 4,
				tview.NewTableCell(queue.Packages.Client.Metadata.Protocol).
					SetTextColor(tcell.ColorWhite).
					SetAlign(tview.AlignCenter))

			// ANSWERS
			t.Table.SetCell(stRow, 5,
				tview.NewTableCell(fmt.Sprint(len(queue.Packages.Server.Payload.Answers))).
					SetTextColor(tcell.ColorWhite).
					SetAlign(tview.AlignCenter))

			// DURATION (MS)
			t.Table.SetCell(stRow, 6,
				tview.NewTableCell(queue.Duration.String()).
					SetTextColor(tcell.ColorWhite).
					SetAlign(tview.AlignCenter))
			stRow++
		}

		t.App.Draw()

	}
}
