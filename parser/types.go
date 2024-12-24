package parser

import (
	"net"
	"time"
)

// DNSRequest will return a DNS request with its UDP response if exists
type DNSRequest struct {
	TrackID  string        `json:"id"`
	Packages DNSPackages   `json:"packages,omitempty"`
	Duration time.Duration `json:"duration_ms,omitempty"`
}

// DNSPackages defines peers based on request (client) and response (server) DNS network packets
type DNSPackages struct {
	Client DNSNetworkPackage `json:"client,omitempty"`
	Server DNSNetworkPackage `json:"server,omitempty"`
}

// DNSNetworkPackage is an abstaction of a single DNS UDP package
type DNSNetworkPackage struct {
	TrackID   string                    `json:"id,omitempty"`
	Metadata  DNSNetworkPackageMetadata `json:"metadata,omitempty"`
	Payload   DNSNetworkPackagePayload  `json:"payload,omitempty"`
	Timestamp time.Time                 `json:"timestamp,omitempty"`
}

// DNSNetworkPackageMetadata will specify metadata for a DNS network package
type DNSNetworkPackageMetadata struct {
	Protocol         string `json:"protocol"`
	NetworkInterface string `json:"iface"`
	Namespace        string `json:"namespace"`
	Pod              string `json:"pod"`
}

// DNSNetworkPackagePayload will specify DNS query' payload for a DNS network package
type DNSNetworkPackagePayload struct {
	// example: request
	SrcIP     net.IP        `json:"src_ip"`
	DstIP     net.IP        `json:"dst_ip"`
	Questions []DNSQuestion `json:"questions"`
	Answers   []DNSAnswer   `json:"answer,omitempty"`
}

// DNSQuestion will format a DNS question query
type DNSQuestion struct {
	Name  string `json:"name,omitempty"`
	Class string `json:"class,omitempty"`
	Type  string `json:"type,omitempty"`
}

// DNSAnswer will format a DNS question query
type DNSAnswer struct {
	Name  string `json:"name,omitempty"`
	Class string `json:"class,omitempty"`
	Type  string `json:"type,omitempty"`
	IP    net.IP `json:"ip,omitempty"`
}
