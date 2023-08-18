package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

    // "github.com/fatih/color"
)

// Core functionality of the script
// Iterate through each port and automate launching tools
func portsIterator(targetIP string, baseDir string, openPorts string) {
	// ports covered so far: "21,22,25,465,587,53,79,80,443,8080,88,110,143,993,995,111,137,138,139,445,161,162,623,873,1433,1521"
	portsArray := strings.Split(openPorts, ",")

	// Iterate over each port in the array
	for _, port := range portsArray {
		switch port {
		case "21":
			// Handle port 21
			fmt.Printf("%s\n", green("[+] FTP service detected. Running FTP nmap enum scripts."))
			ftpDir := baseDir + "ftp/"
			customMkdir(ftpDir)

			// Running Nmap scripts for FTP
			cmd := exec.Command("nmap", "-sV", "-n", "-Pn", "-p21", targetIP, "--script", "ftp-* and not brute", "-v")
			nmapOutput, err := cmd.CombinedOutput()
			if err != nil {
				fmt.Println("Error running nmap:", err)
			}
			nmapOutputFile := ftpDir + "ftp_enum.nmap"
			err = os.WriteFile(nmapOutputFile, nmapOutput, 0644)
			if err != nil {
				fmt.Println("Error writing nmap output:", err)
			}
        case "22":
			fmt.Printf("%s\n", green("[+] SSH service detected. Running SSH nmap enum scripts."))
            sshDir := baseDir + "ssh/"
			customMkdir(sshDir)

        case "25", "465", "587":
            fmt.Printf("%s %s\n", green("[+] SMTP service detected. Running SMTP enum tools in port"), yellow(port))
            smtpDir := baseDir + "smtp/"
			customMkdir(smtpDir)

        case "53":
            fmt.Printf("%s\n", green("[+] DNS service detected. Running DNS nmap enum scripts."))
            dnsDir := baseDir + "dns/"
			customMkdir(dnsDir)

        case "79":
            fmt.Printf("%s\n", green("[+] Finger service detected. Running Finger nmap enum scripts."))
            fingerDir := baseDir + "finger/"
			customMkdir(fingerDir)

        case "80", "443", "8080":
            fmt.Printf("%s\n", green("[+] HTTP service detected. Running Web enum tools."))
            httpDir := baseDir + "http/"
			customMkdir(httpDir)

        case "88":
            fmt.Printf("%s\n", green("[+] Kerberos service detected. Running Nmap enum scripts."))
            kerberosDir := baseDir + "kerberos/"
			customMkdir(kerberosDir)
            
            filePath := kerberosDir + "potential_DC_commands.txt"
            message := `Potential DC found. Enumerate further.
                        Get the name of the domain and chuck it to:
                        nmap -p 88 \ 
                        --script=krb5-enum-users \
                        --script-args krb5-enum-users.realm=\"{Domain_Name}\" \\\n,userdb={Big_Userlist} \\\n{IP}"`
            writeTextToFile(filePath, message)

        case "110":
            fmt.Println("POP3 - Post Office Protocol")
        case "143":
            fmt.Println("IMAP - Internet Message Access Protocol")
        case "993":
            fmt.Println("IMAP - Secure")
        case "995":
            fmt.Println("POP3 - Secure")
        case "111":
            fmt.Println("RPC - Remote Procedure Control")
        case "137":
            fmt.Println("NetBIOS Name Service")
        case "138":
            fmt.Println("NetBIOS Datagram Service")
        case "139":
            fmt.Println("NetBIOS Session Service")
        case "445":
            fmt.Println("SMB - Server Message Block")
        case "161":
            fmt.Println("SNMP - Simple Network Management Protocol")
        case "162":
            fmt.Println("SNMP - Trap")
        case "623":
            fmt.Println("ASF - Remote Management and Control Protocol")
        case "873":
            fmt.Println("RSYNC - Remote Sync")
        case "1433":
            fmt.Println("Microsoft SQL Server")
        case "1521":
            fmt.Println("Oracle Database")
        default:
            fmt.Println("Unknown port")
        }
	}

}