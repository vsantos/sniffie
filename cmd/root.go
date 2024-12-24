/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"
	"go-udp-study/parser"
	"go-udp-study/ui"
	"net"
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "snifie",
	Short: "An 'observable' DNS traffic sniffer",
	Long: `A longer description that spans multiple lines and likely contains
examples and usage of using your application. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	// Run: func(cmd *cobra.Command, args []string) { },
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Mark using `MarkPersistentFlagRequired` ")
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.MarkPersistentFlagRequired("inet"); err != nil {
		fmt.Println(err.Error())
		return
	}

	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	// rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.go-udp-study.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	// rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	var inet string
	var output string

	rootCmd.PersistentFlags().StringVarP(&inet, "inet", "i", "en0", "Network interface. Default: en0")
	rootCmd.PersistentFlags().StringVarP(&output, "output", "o", "table", "Sniff output. Options: table,json")

	rootCmd.MarkPersistentFlagRequired("inet")
	rootCmd.MarkPersistentFlagRequired("output")

	switch output {
	case "table":
		// fmt.Println("draw table")
		t := ui.NewTUI()
		ui.SetTable(t.Table)
		go ui.UpdateTime(t)

		if err := t.Start(); err != nil {
			panic(err)
		}

	default:
		if len(parser.DNSRequestQueue) <= 0 {
			fmt.Println(parser.DNSRequestQueue)
		}

	}

	handle, err := pcap.OpenLive(inet, 1500, true, pcap.BlockForever)
	fmt.Println(inet)
	if err != nil {
		log.Error("Could not OpenLive: ", err.Error())
		os.Exit(1)
	}

	_, err = net.InterfaceByName(inet)
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
	err = pcapWriter.WriteFileHeader(1500, handle.LinkType())
	if err != nil {
		log.Error("Could not write pcap header: ", err.Error())
		os.Exit(1)
	}

	// Reading packages
	var pc parser.DNSParser
	pc = &parser.DNSParserConfig{
		Iface: inet,
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

		err = pcapWriter.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
		if err != nil {
			log.Error("Could not write a packet to a pcap writer: ", err.Error())

			continue
		}
	}
}
