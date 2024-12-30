package manager

import (
	"fmt"
	"net"
	"os"
	"sniffie/parser"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"github.com/gopacket/gopacket/pcapgo"
	log "github.com/sirupsen/logrus"
)

var pcapWriter *pcapgo.Writer

type SnifferConfig struct {
	Net          NetConfig
	Integrations SnifferIntegration
	Output       SnifferOutput
	// Logger: ""
}

type NetConfig struct {
	InterfaceName string
	GeneratePcap  bool
}

type SnifferIntegration struct {
	Name    string
	Enabled bool
	Opts    interface{}
}

type kubernetes struct {
	Name    string
	Enabled bool
	Opts    interface{}
}
type SnifferOutput struct {
	OutputType string // ex: pcap
	OutputPath string //'./sniffie'
}

// Sniffer will sniff something
type Sniffer interface {
	Watch()
}

func init() {
	log.SetFormatter(&log.JSONFormatter{})
}

func (s *SnifferConfig) Watch() {
	log.Info("Watching packets with the following config: ", s)

	handle, err := pcap.OpenLive(s.Net.InterfaceName, 262144, true, pcap.BlockForever)
	fmt.Println(s.Net.InterfaceName)
	if err != nil {
		log.Error("Could not OpenLive: ", err.Error())
		os.Exit(1)
	}

	_, err = net.InterfaceByName(s.Net.InterfaceName)
	if err != nil {
		log.Error("Could not get interface by name : ", err.Error())
		os.Exit(1)
	}

	// Start new Source reader.
	source := gopacket.NewPacketSource(handle, handle.LinkType())

	// Reading packages
	var pc parser.DNSParser
	pc = &parser.DNSParserConfig{
		Iface: s.Net.InterfaceName,
		Opts: &parser.DNSParserConfigOpts{
			ResolvePodNames: true,
		},
	}

	// log.Infoln("sniffing traffic")

	for packet := range source.Packets() {
		layer := packet.Layer(layers.LayerTypeEthernet)
		_, ok := layer.(*layers.Ethernet)
		if !ok {
			log.Error("Could not get Ethernet layer")
			continue
		}

		// We only support UDP packages for now
		_, _, err := pc.UDP(packet)
		if err != nil {
			panic(err)
		}

		if s.Net.GeneratePcap {
			fileWriter, _ := os.Create(s.Output.OutputPath)
			defer fileWriter.Close()
			// fileWriter := bytes.NewBuffer(nil)
			pcapWriter = pcapgo.NewWriterNanos(fileWriter)
			err = pcapWriter.WriteFileHeader(262144, handle.LinkType())
			if err != nil {
				log.Error("Could not write pcap header: ", err.Error())
				os.Exit(1)
			}

			err = pcapWriter.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
			if err != nil {
				log.Error("Could not write a packet to a pcap writer: ", err.Error())

				continue
			}
		}
	}
}
