package main

import (
	"encoding/xml"
	"fmt"
	"os"
	"strings"
)

// NmapRun represents the root element of an nmap XML file
type NmapRun struct {
	XMLName xml.Name `xml:"nmaprun"`
	Hosts   []Host   `xml:"host"`
	Start   string   `xml:"start,attr"`
	Version string   `xml:"version,attr"`
}

// Host represents a scanned host
type Host struct {
	XMLName  xml.Name   `xml:"host"`
	Status   Status     `xml:"status"`
	Address  []Address  `xml:"address"`
	Ports    Ports      `xml:"ports"`
	Hostname []Hostname `xml:"hostnames>hostname"`
}

// Status represents the host status
type Status struct {
	State     string `xml:"state,attr"`
	Reason    string `xml:"reason,attr"`
	ReasonTTL string `xml:"reason_ttl,attr"`
}

// Address represents an IP or MAC address
type Address struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
	Vendor   string `xml:"vendor,attr"`
}

// Ports represents a collection of ports
type Ports struct {
	Port []Port `xml:"port"`
}

// Port represents a scanned port
type Port struct {
	Protocol string  `xml:"protocol,attr"`
	PortID   int     `xml:"portid,attr"`
	State    State   `xml:"state"`
	Service  Service `xml:"service"`
}

// State represents the port state
type State struct {
	State     string `xml:"state,attr"`
	Reason    string `xml:"reason,attr"`
	ReasonTTL string `xml:"reason_ttl,attr"`
}

// Service represents service information
type Service struct {
	Name      string `xml:"name,attr"`
	Product   string `xml:"product,attr"`
	Version   string `xml:"version,attr"`
	ExtraInfo string `xml:"extrainfo,attr"`
	Method    string `xml:"method,attr"`
	Conf      string `xml:"conf,attr"`
}

// Hostname represents a hostname
type Hostname struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <nmap-xml-file>\n", os.Args[0])
		os.Exit(1)
	}

	filename := os.Args[1]

	// Read the XML file
	data, err := os.ReadFile(filename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
		os.Exit(1)
	}

	// Parse the XML
	var nmapRun NmapRun
	err = xml.Unmarshal(data, &nmapRun)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing XML: %v\n", err)
		os.Exit(1)
	}

	// Print header
	fmt.Println("Hostname\tIP Address\tPorts")

	// Process each host
	for _, host := range nmapRun.Hosts {
		// Skip hosts that are down
		if host.Status.State != "up" {
			continue
		}

		// Extract IP address (prefer IPv4)
		var ipAddress string
		for _, addr := range host.Address {
			if addr.AddrType == "ipv4" {
				ipAddress = addr.Addr
				break
			}
		}
		// Fallback to first address if no IPv4 found
		if ipAddress == "" && len(host.Address) > 0 {
			for _, addr := range host.Address {
				if addr.AddrType == "ipv4" || addr.AddrType == "ipv6" {
					ipAddress = addr.Addr
					break
				}
			}
		}
		if ipAddress == "" && len(host.Address) > 0 {
			ipAddress = host.Address[0].Addr
		}

		// Extract hostname(s)
		var hostnames []string
		for _, hostname := range host.Hostname {
			hostnames = append(hostnames, hostname.Name)
		}
		hostnameStr := strings.Join(hostnames, ",")
		if hostnameStr == "" {
			hostnameStr = "-"
		}

		// Extract open ports
		var ports []string
		for _, port := range host.Ports.Port {
			if port.State.State == "open" {
				portStr := fmt.Sprintf("%d/%s", port.PortID, port.Protocol)
				if port.Service.Name != "" {
					portStr += fmt.Sprintf(" (%s", port.Service.Name)
					if port.Service.Product != "" {
						portStr += fmt.Sprintf(" %s", port.Service.Product)
						if port.Service.Version != "" {
							portStr += fmt.Sprintf(" %s", port.Service.Version)
						}
					}
					portStr += ")"
				}
				ports = append(ports, portStr)
			}
		}
		portsStr := strings.Join(ports, ", ")
		if portsStr == "" {
			portsStr = "-"
		}

		// Print row
		fmt.Printf("%s\t%s\t%s\n", hostnameStr, ipAddress, portsStr)
	}
}
