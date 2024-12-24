package parser

import (
	"os"
	"strconv"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

var (
	// DNSPackagesQueue will hold DNSNetworkPackages for wrapping up duration
	DNSPackagesQueue map[string]DNSNetworkPackage
	//DNSRequestQueue will hold requests for posterior usage
	DNSRequestQueue []DNSRequest
)

func init() {
	DNSPackagesQueue = make(map[string]DNSNetworkPackage)
	DNSRequestQueue = []DNSRequest{}
}

// GetDNSPackage will get a single packet
func GetDNSPackage(iface string, dns *layers.DNS, packet gopacket.Packet) (DNSNetworkPackage, error) {

	dnsPkg := &DNSNetworkPackage{}
	dnsPkg.TrackID = strconv.Itoa(int(dns.ID))
	dnsPkg.Timestamp = packet.Metadata().Timestamp
	dnsPkg.Payload.SrcIP = packet.NetworkLayer().NetworkFlow().Src().Raw()
	dnsPkg.Payload.DstIP = packet.NetworkLayer().NetworkFlow().Dst().Raw()
	dnsPkg.Metadata.NetworkInterface = iface
	dnsPkg.Metadata.Protocol = "udp"
	// temporiarly
	dnsPkg.Metadata.Namespace = "debug-nslookup"
	h, _ := os.Hostname()
	dnsPkg.Metadata.Pod = h

	if dns.Questions != nil || len(dns.Questions) > 0 {
		var q []DNSQuestion

		for _, questions := range dns.Questions {
			q = append(q, DNSQuestion{
				Name:  string(questions.Name),
				Class: questions.Class.String(),
				Type:  questions.Type.String(),
			})
		}

		dnsPkg.Payload.Questions = q
	}

	if dns.Answers != nil || len(dns.Answers) > 0 {

		var a []DNSAnswer
		for _, answer := range dns.Answers {

			a = append(a, DNSAnswer{
				Name:  string(answer.Name),
				Class: answer.Class.String(),
				Type:  answer.Type.String(),
				IP:    answer.IP,
			})
		}
		dnsPkg.Payload.Answers = a
	}

	return *dnsPkg, nil
}
