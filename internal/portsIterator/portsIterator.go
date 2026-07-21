package portsIterator

import (
	"fmt"

	"github.com/0x5ubt13/enumeraga/internal/checks"
	"github.com/0x5ubt13/enumeraga/internal/portsIterator/protocols"
	"github.com/0x5ubt13/enumeraga/internal/utils"
)

// Run iterates through each port, groups by protocol and automates launching tools
func Run(openPortsSlice []string) {

	for _, port := range openPortsSlice {
		routePort(port, openPortsSlice)
	}
}

// routePort routes a port to its appropriate protocol handler
func routePort(port string, openPortsSlice []string) {
	switch port {
	// File Transfer
	case "20", "21":
		protocols.FTP(port)
	case "873":
		protocols.Rsync(port)
	case "2049":
		protocols.NFS(port)

	// Remote Access
	case "22":
		protocols.SSH(port)
	case "23":
		protocols.TELNET(port)
	case "3389":
		protocols.RDP(port)
	case "5985", "5986":
		protocols.WinRM(port)

	// Mail
	case "25", "465", "587":
		protocols.SMTP(port)
	case "143", "993":
		protocols.IMAP(port)
	case "110", "995":
		protocols.POP3(port)

	// Web
	case "80", "8080":
		if protocols.IsHTTPService( fmt.Sprintf("http://%s:%s", utils.Target, port)) { 
			protocols.HTTP(port,"http")
		}
	case "443":
		if protocols.IsHTTPSService( fmt.Sprintf("https://%s:%s", utils.Target, port)) {
			protocols.HTTP(port,"https")
		}


	// SMB/NetBIOS
	case "137", "138", "139", "445":
		protocols.SMB(port)

	// Directory Services
	case "88":
		protocols.Kerberos(port)
	case "389", "3268":
		protocols.LDAP(port,"ldap")
	case "636", "3269":
		protocols.LDAP(port,"ldaps")

	// Databases
	case "3306":
		protocols.MySQL(port)
	case "1433":
		protocols.MSSQL(port)
	case "1521", "1522", "1523", "1524", "1525", "1526", "1527", "1528", "1529":
		protocols.TNS(port)

	// Miscellaneous
	case "53":
		protocols.DNS(port)
	case "79":
		protocols.Finger(port)
	case "111":
		protocols.RPC(port)
	case "113":
		protocols.Ident(port, openPortsSlice)
	case "135", "593":
		protocols.MSRPC(port)
	case "161", "162", "10161", "10162": // UDP
		protocols.SNMP(port)
	case "512", "513", "514":
		protocols.RServices(port)
	case "623":
		protocols.IPMI(port)
	case "10000":
		protocols.Port10000(port)
	case "123":
		protocols.NTP(port)
	case "500":
		protocols.IPSEC(port)

	// Try Detect Service
	default:
		// check for HTTP/HTTPS service
		if protocols.IsHTTPService( fmt.Sprintf("http://%s:%s", utils.Target, port)) { 
			protocols.HTTP(port,"http")
			return
		}
		if protocols.IsHTTPSService( fmt.Sprintf("https://%s:%s", utils.Target, port)) { 
			protocols.HTTP(port,"https")
			return
		}

		// Detection Failed
		if *checks.OptVVerbose {
			utils.PrintSafe("%s %s %s %s %s\n", utils.Red("[-] Port"), utils.Yellow(port), utils.Red("detected, but I don't know how to handle it yet. Please check the"), utils.Cyan("main Nmap"), utils.Red("scan"))
		}
	}
}

