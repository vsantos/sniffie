package ui

import (
	"fmt"
	"sniffie/parser"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

type TUI struct {
	App   *tview.Application
	Table *tview.Table
	Flex  *tview.Flex
}

// func Refresh(refreshInterval time.Duration) {
// 	tick := time.NewTicker(refreshInterval)
// 	for {
// 		select {
// 		case <-tick.C:
// 			App.Draw()
// 		}
// 	}
// }

func drawTime(screen tcell.Screen, x int, y int, width int, height int) (int, int, int, int) {
	// timeStr := time.Now().Format("Current time is 15:04:05")
	// str := strconv.Itoa(len(parser.DNSRequestQueue))
	// fmt.Println("str")
	tview.Print(screen, fmt.Sprint(parser.DNSRequestQueue), x, height/2, width, tview.AlignCenter, tcell.ColorLime)
	// tview.NewTableCell("hi")

	return 0, 0, 0, 0
}

func NewTUI() TUI {
	app := tview.NewApplication()

	table := tview.NewTable().SetBorders(true)
	// table.SetDrawFunc(SetTable(table))

	flex := tview.NewFlex().
		// AddItem(tview.NewBox().SetBorder(true).SetTitle("Left (1/2 x width of Top)"), 0, 1, false).
		AddItem(table, 0, 1, false)

	return TUI{
		App:   app,
		Table: table,
		Flex:  flex,
	}
}

func (t *TUI) Start() error {
	go t.App.SetRoot(t.Flex, true).EnableMouse(true).SetFocus(t.Flex).Run()
	return nil
}
