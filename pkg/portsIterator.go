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

        case "110", "143", "993", "995":
            fmt.Printf("%s\n", green("[+] IMAP / POP3 service detected. Running IMAP / POP3 enum scripts."))
            mailDir := baseDir + "imap_pop3/"
			customMkdir(mailDir)

        case "111": //UDP
            fmt.Printf("%s\n", green("[+] RPC service detected. Running RPC nmap enum scripts."))
            rpcDir := baseDir + "rpc/"
			customMkdir(rpcDir)

        case "113":
            fmt.Printf("%s\n", green("[+] Ident service detected. Running Ident enum scripts."))
            identDir := baseDir + "ident/"
			customMkdir(identDir)
            
        case "135":
            fmt.Printf("%s\n", green("[+] MSRPC detected. Running MSRPC enum tools."))
            msrpcDir := baseDir + "msrpc/"
			customMkdir(msrpcDir)

        case "137","138","139","445":
            fmt.Printf("%s\n", green("[+] NetBIOS/SMB detected. Running NB/SMB enum tools."))
            nbSmbDir := baseDir + "nb_smb/"
			customMkdir(nbSmbDir)
            // Remember to add enum4linux-ng

        case "161","162","10161","10162": // UDP
            fmt.Printf("%s\n", green("[+] SNMP detected. Running SNMP enum tools."))
            snmpDir := baseDir + "snmp/"
			customMkdir(snmpDir)

            fmt.Println("SNMP - Simple Network Management Protocol")
        case "389","636","3268","3269":
            fmt.Printf("%s\n", green("[+] LDAP detected. Running LDAP enum tools."))
            ldapDir := baseDir + "ldap/"
			customMkdir(ldapDir)

        case "512","513","514":
            fmt.Printf("%s\n", green("[+] R-Services detected. Running R-Services enum tools."))
            rDir := baseDir + "r-services/"
			customMkdir(rDir)

        case "623":
            fmt.Printf("%s\n", green("[+] IPMI detected. Running IPMI enum tools."))
            ipmiDir := baseDir + "ipmi/"
			customMkdir(ipmiDir)

        case "873":
            fmt.Printf("%s\n", green("[+] RSync detected. Running RSync enum tools."))
            rsyncDir := baseDir + "rsync/"
			customMkdir(rsyncDir)

        case "1433":
            fmt.Printf("%s\n", green("[+] MSSQL detected. Running MSSQL enum tools."))
            mssqlDir := baseDir + "mssql/"
			customMkdir(mssqlDir)

        case "1521":
            fmt.Printf("%s\n", green("[+] Oracle TNS detected. Running Oracle TNS enum tools."))
            tnsDir := baseDir + "tns/"
			customMkdir(tnsDir)

        case "2049":
            fmt.Printf("%s\n", green("[+] NFS service detected. Running NFS enum tools."))
            nfsDir := baseDir + "nfs/"
			customMkdir(nfsDir)

        case "3306":
            fmt.Printf("%s\n", green("[+] MySQL detected. Running MySQL enum tools."))
            mysqlDir := baseDir + "mysql/"
			customMkdir(mysqlDir)

        case "3389":
            fmt.Printf("%s\n", green("[+] RDP detected. Running RDP enum tools."))
            rdpDir := baseDir + "rdp/"
			customMkdir(rdpDir)

        case "5985","5986":
            fmt.Printf("%s\n", green("[+] WinRM service detected. Running WinRM enum tools."))
            winrmDir := baseDir + "winrm/"
			customMkdir(winrmDir)

        case "10000":
            // if not webmin, ndmp. 
            continue
            
        default:
            fmt.Println("Unknown port")
        }
	}

}