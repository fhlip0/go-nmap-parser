# Go Nmap Parser

A simple Golang application that parses nmap XML output files and displays the results in a human-readable format.

## Features

- Parses standard nmap XML output files
- Displays host information including:
  - Host status (up/down)
  - IP and MAC addresses
  - Hostnames
  - Open ports and their states
  - Service information (name, product, version)

## Requirements

- Go 1.21 or later

## Installation

```bash
go build -o nmap-parser main.go
```

## Usage

First, generate an nmap XML file:

```bash
nmap -oX scan.xml example.com
```

Then parse it with the application:

```bash
./nmap-parser scan.xml
```

Or run directly with Go:

```bash
go run main.go scan.xml
```

## Example Output

```
Nmap Scan Results
================
Version: 7.94
Start Time: 1234567890
Total Hosts: 1

Host 1:
  Status: up (syn-ack)
  ipv4 Address: 192.168.1.1
  Hostnames:
    - router.local (PTR)
  Ports:
    22/tcp: open (syn-ack)
      Service: ssh (OpenSSH 8.2)
    80/tcp: open (syn-ack)
      Service: http (nginx 1.18.0)
    443/tcp: open (syn-ack)
      Service: https (nginx 1.18.0)
```

## License

MIT

