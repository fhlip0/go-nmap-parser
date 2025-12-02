package main

import (
	"encoding/csv"
	"encoding/xml"
	"flag"
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

// getIPAddress extracts the IP address from a host, preferring IPv4
func getIPAddress(host Host) string {
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
	return ipAddress
}

// getHostname extracts hostname(s) from a host
func getHostname(host Host) string {
	var hostnames []string
	for _, hostname := range host.Hostname {
		hostnames = append(hostnames, hostname.Name)
	}
	hostnameStr := strings.Join(hostnames, ",")
	if hostnameStr == "" {
		hostnameStr = "-"
	}
	return hostnameStr
}

func main() {
	csvFlag := flag.Bool("csv", false, "Output results in CSV format with IP:PORT format")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags] <nmap-xml-file>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\nFlags:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(1)
	}

	filename := flag.Arg(0)

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

	if *csvFlag {
		// CSV output format: one row per port with IP:PORT
		writer := csv.NewWriter(os.Stdout)
		defer writer.Flush()

		// Write CSV header
		writer.Write([]string{"Hostname", "IP:PORT", "Protocol"})

		// Process each host
		for _, host := range nmapRun.Hosts {
			// Skip hosts that are down
			if host.Status.State != "up" {
				continue
			}

			ipAddress := getIPAddress(host)
			hostnameStr := getHostname(host)

			// Write one row per open port
			for _, port := range host.Ports.Port {
				if port.State.State == "open" {
					ipPort := fmt.Sprintf("%s:%d", ipAddress, port.PortID)
					protocol := strings.ToUpper(port.Protocol)
					writer.Write([]string{hostnameStr, ipPort, protocol})
				}
			}
		}
	} else {
		// Tab-separated output format (default)
		fmt.Println("Hostname\tIP Address\tPorts")

		// Process each host
		for _, host := range nmapRun.Hosts {
			// Skip hosts that are down
			if host.Status.State != "up" {
				continue
			}

			ipAddress := getIPAddress(host)
			hostnameStr := getHostname(host)

			// Extract open ports grouped by protocol
			portsByProtocol := make(map[string][]int)
			for _, port := range host.Ports.Port {
				if port.State.State == "open" {
					protocol := strings.ToUpper(port.Protocol)
					portsByProtocol[protocol] = append(portsByProtocol[protocol], port.PortID)
				}
			}

			var portGroups []string
			// Order: TCP first, then UDP, then others alphabetically
			protocolOrder := []string{"TCP", "UDP"}
			processedProtocols := make(map[string]bool)

			// Process TCP and UDP first
			for _, proto := range protocolOrder {
				if ports, ok := portsByProtocol[proto]; ok {
					portNums := make([]string, len(ports))
					for i, p := range ports {
						portNums[i] = fmt.Sprintf("%d", p)
					}
					portGroups = append(portGroups, fmt.Sprintf("%s %s", strings.Join(portNums, ", "), proto))
					processedProtocols[proto] = true
				}
			}

			// Process remaining protocols
			for proto, ports := range portsByProtocol {
				if !processedProtocols[proto] {
					portNums := make([]string, len(ports))
					for i, p := range ports {
						portNums[i] = fmt.Sprintf("%d", p)
					}
					portGroups = append(portGroups, fmt.Sprintf("%s %s", strings.Join(portNums, ", "), proto))
				}
			}

			portsStr := strings.Join(portGroups, ", ")
			if portsStr == "" {
				portsStr = "-"
			}

			// Print row
			fmt.Printf("%s\t%s\t%s\n", hostnameStr, ipAddress, portsStr)
		}
	}
}
