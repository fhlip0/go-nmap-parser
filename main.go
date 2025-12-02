package main

import (
	"encoding/xml"
	"fmt"
	"os"
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
	XMLName   xml.Name  `xml:"host"`
	Status   Status    `xml:"status"`
	Address  []Address `xml:"address"`
	Ports    Ports     `xml:"ports"`
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
	Protocol string `xml:"protocol,attr"`
	PortID   int    `xml:"portid,attr"`
	State    State  `xml:"state"`
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
	Name       string `xml:"name,attr"`
	Product    string `xml:"product,attr"`
	Version    string `xml:"version,attr"`
	ExtraInfo  string `xml:"extrainfo,attr"`
	Method     string `xml:"method,attr"`
	Conf       string `xml:"conf,attr"`
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

	// Display results
	fmt.Printf("Nmap Scan Results\n")
	fmt.Printf("================\n")
	fmt.Printf("Version: %s\n", nmapRun.Version)
	fmt.Printf("Start Time: %s\n", nmapRun.Start)
	fmt.Printf("Total Hosts: %d\n\n", len(nmapRun.Hosts))

	for i, host := range nmapRun.Hosts {
		fmt.Printf("Host %d:\n", i+1)
		fmt.Printf("  Status: %s (%s)\n", host.Status.State, host.Status.Reason)
		
		// Print addresses
		for _, addr := range host.Address {
			fmt.Printf("  %s Address: %s", addr.AddrType, addr.Addr)
			if addr.Vendor != "" {
				fmt.Printf(" (%s)", addr.Vendor)
			}
			fmt.Println()
		}
		
		// Print hostnames
		if len(host.Hostname) > 0 {
			fmt.Printf("  Hostnames:\n")
			for _, hostname := range host.Hostname {
				fmt.Printf("    - %s (%s)\n", hostname.Name, hostname.Type)
			}
		}
		
		// Print ports
		if len(host.Ports.Port) > 0 {
			fmt.Printf("  Ports:\n")
			for _, port := range host.Ports.Port {
				fmt.Printf("    %d/%s: %s", port.PortID, port.Protocol, port.State.State)
				if port.State.Reason != "" {
					fmt.Printf(" (%s)", port.State.Reason)
				}
				fmt.Println()
				
				// Print service information if available
				if port.Service.Name != "" {
					fmt.Printf("      Service: %s", port.Service.Name)
					if port.Service.Product != "" {
						fmt.Printf(" (%s", port.Service.Product)
						if port.Service.Version != "" {
							fmt.Printf(" %s", port.Service.Version)
						}
						fmt.Printf(")")
					}
					if port.Service.ExtraInfo != "" {
						fmt.Printf(" - %s", port.Service.ExtraInfo)
					}
					fmt.Println()
				}
			}
		} else {
			fmt.Printf("  No open ports found\n")
		}
		
		fmt.Println()
	}
}

