package main

import (
	"fmt"
	"strings"
	// "os"
	// "os/exec"
)

// Core functionality of the script
// Iterate through each port and automate launching tools
func portsIterator(target string, baseDir string, openPortsSlice []string) {
    var (
        caseDir string
        visitedSMTP, visitedHTTP, visitedIMAP, visitedSMB, visitedSNMP, visitedLDAP, visitedRsvc, visitedWinRM bool
    )

    // DEV: Debugging purposes
    if *optDbg {fmt.Printf("%s %s\n", "Debug: baseDir: ", baseDir)} 

    // Bruteforce flag?
    if *optBrute {
        if !*optQuiet {
            fmt.Printf("%s\n", 
            cyan("[*] Bruteforce flag detected. Activating fuzzing and bruteforcing tools where applicable."))
            getWordlists()
        }

    // Loop through every port
    for _, port := range openPortsSlice {
		switch port {
		case "20", "21":
			caseDir = protocolDetected(baseDir, "FTP")
            nmapOutputFile := caseDir + "ftp_scan"
            nmapNSEScripts := "ftp-* and not brute"
            individualPortScannerWithNSEScripts(target, "20,21", nmapOutputFile, nmapNSEScripts)
            // individualPortScanner(target, port, nmapOutputFile)
            hydraBruteforcing(target, caseDir, "ftp")

        case "22":
            caseDir = protocolDetected("SSH")
            nmapOutputFile := caseDir + "ssh_scan"
            nmapNSEScripts := "ssh-* and not brute"
            individualPortScannerWithNSEScripts(target, port, nmapOutputFile, nmapNSEScripts)
            hydraBruteforcing(target, caseDir, "ssh")

        case "25", "465", "587":
            if visitedSMTP { continue }

            caseDir = protocolDetected("SMTP")
            nmapOutputFile := caseDir + "smtp_scan"
            nmapNSEScripts := "smtp-commands,smtp-enum-users,smtp-open-relay"
            individualPortScannerWithNSEScripts(target, "25,465,587", nmapOutputFile, nmapNSEScripts)

        case "53":
            caseDir = protocolDetected("DNS")
            nmapOutputFile := caseDir + "dns_scan"
            nmapNSEScripts := "*dns*"
            individualPortScannerWithNSEScripts(target, port, nmapOutputFile, nmapNSEScripts)

        case "79":
            caseDir = protocolDetected("Finger")
            nmapOutputFile := caseDir + "finger_scan"
            individualPortScanner(target, port, nmapOutputFile)
            
            msfArgs := []string{"msfconsole", "-q", "-x", fmt.Sprintf("use auxiliary/scanner/finger/finger_users;set rhost %s;run;exit", target)}
            runTool(msfArgs, target, caseDir)

        case "80", "443", "8080":
            if visitedHTTP { continue }
            
            // TODO, skipping for now
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
            if visitedIMAP { continue }

            caseDir = protocolDetected("IMAP/POP3")
            nmapOutputFile := caseDir + "imap_pop3_scan"
            individualPortScanner(target, "110,143,993,995", nmapOutputFile)

            // Openssl
            openSSLArgs := []string{"openssl", "s_client", "-connect", fmt.Sprintf("%s:imaps", target)}
            runTool(openSSLArgs, target, caseDir)

            // NC banner grabbing
            ncArgs := []string{"nc", "-nv", target, port}
            runTool(ncArgs, target, caseDir)

        case "111": //TODO: implement UDP scan to catch RPC
            caseDir = protocolDetected("RPC")
            nmapOutputFile := caseDir + "rpc"
            individualPortScanner(target, port, nmapOutputFile)

        case "113":
            caseDir = protocolDetected("Ident")
            nmapOutputFile := caseDir + "ident"
            individualPortScanner(target, port, nmapOutputFile)
            
            // ident-user-enum
            spacedPorts := strings.Join(openPortsSlice, " ")
            identUserEnumArgs := []string{"ident-user-enum", target, spacedPorts}
            runTool(identUserEnumArgs, target, caseDir)

        case "135":
            caseDir = protocolDetected("MSRPC")
            nmapOutputFile := caseDir + "msrpc"
            individualPortScanner(target, port, nmapOutputFile)

            rpcDumpArgs := []string{"rpcdump", port, } //TODO: rethink runTool()
            runTool()

        case "137","138","139","445":
            if visitedSMB { continue }
            fmt.Printf("%s\n", green("[+] NetBIOS/SMB detected. Running NB/SMB enum tools."))
            nbSmbDir := baseDir + "nb_smb/"
			customMkdir(nbSmbDir)
            // Remember to add enum4linux-ng

        case "161","162","10161","10162": // UDP
            if visitedSNMP { continue }
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
            // if not webmin, enum ndmp. 
            continue

        default:
            if *optVVervose {fmt.Printf("%s %s %s %s %s\n", red("[-] Port"), yellow(port), red("detected, but I don't know how to handle it yet. Please check the"), cyan("main Nmap"), red("scan"))}
        }
	}
    
    printCustomTripleMsg("green", "yellow", "[+] Done! All well-known ports included in Enumeraga for", target, "were successfully parsed.")
}