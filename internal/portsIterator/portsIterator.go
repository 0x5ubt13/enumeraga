package portsIterator

import (
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
		protocols.FTP()
	case "873":
		protocols.Rsync()
	case "2049":
		protocols.NFS()

	// Remote Access
	case "22":
		protocols.SSH()
	case "3389":
		protocols.RDP()
	case "5985", "5986":
		protocols.WinRM()

	// Mail
	case "25", "465", "587":
		protocols.SMTP()
	case "110", "143", "993", "995":
		protocols.IMAP()

	// Web
	case "80", "443", "8080":
		protocols.HTTP()

	// SMB/NetBIOS
	case "137", "138", "139", "445":
		protocols.SMB()

	// Directory Services
	case "88":
		protocols.Kerberos()
	case "389", "636", "3268", "3269":
		protocols.LDAP()

	// Databases
	case "3306":
		protocols.MySQL()
	case "1433":
		protocols.MSSQL()
	case "1521":
		protocols.TNS()

	// Miscellaneous
	case "53":
		protocols.DNS()
	case "79":
		protocols.Finger()
	case "111":
		protocols.RPC()
	case "113":
		protocols.Ident(openPortsSlice)
	case "135", "593":
		protocols.MSRPC()
	case "161", "162", "10161", "10162": // UDP
		protocols.SNMP()
	case "512", "513", "514":
		protocols.RServices()
	case "623":
		protocols.IPMI()
	case "10000":
		protocols.Port10000()

	default:
		if *checks.OptVVerbose {
			utils.PrintSafe("%s %s %s %s %s\n", utils.Red("[-] Port"), utils.Yellow(port), utils.Red("detected, but I don't know how to handle it yet. Please check the"), utils.Cyan("main Nmap"), utils.Red("scan"))
		}
	}
}
