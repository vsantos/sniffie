package main

import (
	"fmt"
	"go-udp-study/parser"
	"go-udp-study/ui"
	"math/rand"
	"net"
	"os"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/rivo/tview"
	log "github.com/sirupsen/logrus"
)

const (
	interfaceName = "en0"
	snaplen       = 1500
)

func init() {
	log.SetFormatter(&log.JSONFormatter{})
}

const refreshInterval = 500 * time.Millisecond

// var (
// 	app   *tview.Application
// 	flex  *tview.Flex
// 	table *tview.Table
// )

func drawTime(screen tcell.Screen, x int, y int, width int, height int) (int, int, int, int) {
	timeStr := time.Now().Format("Current time is 15:04:05")
	tview.Print(screen, timeStr, x, height/2, width, tview.AlignCenter, tcell.ColorLime)
	return 0, 0, 0, 0
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func RandStringBytes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}

func updateTime(t ui.TUI) {
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

func main() {
	// cols, rows := 10, 40
	t := ui.NewTUI()

	// go refresh()
	ui.SetTable(t.Table)
	go updateTime(t)

	if err := t.Start(); err != nil {
		panic(err)
	}

	// Get handler attached to an interface.
	handle, err := pcap.OpenLive(interfaceName, snaplen, true, pcap.BlockForever)
	if err != nil {
		log.Error("Could not OpenLive: ", err.Error())
		os.Exit(1)
	}

	_, err = net.InterfaceByName(interfaceName)
	if err != nil {
		log.Error("Could not get interface by name : ", err.Error())
		os.Exit(1)
	}

	// Start new Source reader.
	source := gopacket.NewPacketSource(handle, handle.LinkType())

	// This is suppose to be a file writer, but we will use memory, just for simplification.
	fileWriter, _ := os.Create("file.pcap")
	defer fileWriter.Close()
	// fileWriter := bytes.NewBuffer(nil)
	pcapWriter := pcapgo.NewWriterNanos(fileWriter)
	err = pcapWriter.WriteFileHeader(snaplen, handle.LinkType())
	if err != nil {
		log.Error("Could not write pcap header: ", err.Error())
		os.Exit(1)
	}

	// Reading packages
	var pc parser.DNSParser
	pc = &parser.DNSParserConfig{
		Iface: "en0",
	}

	// log.Infoln("sniffing traffic")

	for packet := range source.Packets() {
		layer := packet.Layer(layers.LayerTypeEthernet)
		_, ok := layer.(*layers.Ethernet)
		if !ok {
			log.Error("Could not get Ethernet layer")
			continue
		}

		_, _, err := pc.UDP(packet)
		if err != nil {
			panic(err)
		}

		// if !skip {
		// 	r, _ := json.Marshal(r)
		// 	fmt.Println(string(r))
		// }

		err = pcapWriter.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
		if err != nil {
			log.Error("Could not write a packet to a pcap writer: ", err.Error())

			continue
		}
	}
}
