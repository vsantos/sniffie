package parser

import (
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

type DNSParserConfig struct {
	Iface string
}

// DNSParser will return formatted DNS packages from raw network sniff
type DNSParser interface {
	UDP(packet gopacket.Packet) (r DNSRequest, skip bool, err error)
	TCP(packet gopacket.Packet) (r DNSRequest, skip bool, err error)
}

func (d *DNSParserConfig) UDP(packet gopacket.Packet) (r DNSRequest, skip bool, err error) {

	layer := packet.Layer(layers.LayerTypeDNS)
	dns, ok := layer.(*layers.DNS)
	if !ok {
		// It's not DNS traffic.
		return DNSRequest{}, true, nil
	}

	dnsPkg, err := GetDNSPackage(d.Iface, dns, packet)
	if err != nil {
		return DNSRequest{}, true, err
	}

	_, existentPkg := DNSPackagesQueue[dnsPkg.TrackID]
	if !existentPkg {
		DNSPackagesQueue[dnsPkg.TrackID] = dnsPkg
		return DNSRequest{}, true, nil
	}

	r.TrackID = dnsPkg.TrackID
	r.Duration = 3

	if dnsPkg.Payload.Answers != nil && len(dnsPkg.Payload.Answers) > 0 {
		r.Packages.Client = DNSPackagesQueue[dnsPkg.TrackID]
		r.Packages.Server = dnsPkg
		r.Packages.Server.Payload.SrcIP = dnsPkg.Payload.SrcIP
		r.Packages.Server.Payload.DstIP = dnsPkg.Payload.DstIP
		r.Packages.Client.Payload.SrcIP = dnsPkg.Payload.DstIP
		r.Packages.Client.Payload.DstIP = dnsPkg.Payload.SrcIP
	} else {
		r.Packages.Client = dnsPkg
		r.Packages.Server = DNSPackagesQueue[dnsPkg.TrackID]
		r.Packages.Server.Payload.SrcIP = dnsPkg.Payload.SrcIP
		r.Packages.Server.Payload.DstIP = dnsPkg.Payload.DstIP
		r.Packages.Client.Payload.SrcIP = dnsPkg.Payload.DstIP
		r.Packages.Client.Payload.DstIP = dnsPkg.Payload.SrcIP
	}

	dt := dnsPkg.Timestamp.Sub(DNSPackagesQueue[dnsPkg.TrackID].Timestamp)
	r.Duration = time.Duration(dt)

	delete(DNSPackagesQueue, dnsPkg.TrackID)

	DNSRequestQueue = append(DNSRequestQueue, r)
	return r, false, err
}

func (d *DNSParserConfig) TCP(packet gopacket.Packet) (r DNSRequest, skip bool, err error) {

	// tcpLayer := packet.Layer(layers.LayerTypeTCP)
	// if tcpLayer != nil {
	// 	tcp, _ := tcpLayer.(*layers.TCP)
	// 	fmt.Println(string(tcp.Payload))
	// 	fmt.Println(tcp.TransportFlow().Dst().String())

	// 	// TCP layer variables:
	// 	// SrcPort, DstPort, Seq, Ack, DataOffset, Window, Checksum, Urgent
	// 	// Bool flags: FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS
	// 	// fmt.Printf("From port %d to %d\n", tcp.SrcPort, tcp.DstPort)
	// 	// fmt.Println("Sequence number: ", tcp.Seq)
	// 	// fmt.Println()
	// }

	return DNSRequest{}, false, nil
}
