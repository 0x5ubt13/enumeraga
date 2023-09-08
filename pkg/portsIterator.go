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
        caseDir, filePath, message, nmapOutputFile, nmapNSEScripts string
        visitedFTP, visitedSMTP, visitedHTTP, visitedIMAP, visitedSMB, visitedSNMP, visitedLDAP, visitedRsvc, visitedWinRM bool
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
            if visitedFTP { continue }
            visitedFTP = true

			caseDir = protocolDetected(baseDir, "FTP")
            nmapOutputFile = caseDir + "ftp_scan"
            nmapNSEScripts = "ftp-* and not brute"
            individualPortScannerWithNSEScripts(target, "20,21", nmapOutputFile, nmapNSEScripts)
            // individualPortScanner(target, port, nmapOutputFile)
            hydraBruteforcing(target, caseDir, "ftp")

        case "22":
            caseDir = protocolDetected("SSH")
            nmapOutputFile = caseDir + "ssh_scan"
            nmapNSEScripts = "ssh-* and not brute"
            individualPortScannerWithNSEScripts(target, port, nmapOutputFile, nmapNSEScripts)
            hydraBruteforcing(target, caseDir, "ssh")

        case "25", "465", "587":
            if visitedSMTP { continue }
            visitedHTTP = true

            caseDir = protocolDetected("SMTP")
            nmapOutputFile = caseDir + "smtp_scan"
            nmapNSEScripts = "smtp-commands,smtp-enum-users,smtp-open-relay"
            individualPortScannerWithNSEScripts(target, "25,465,587", nmapOutputFile, nmapNSEScripts)

        case "53":
            caseDir = protocolDetected("DNS")
            nmapOutputFile = caseDir + "dns_scan"
            nmapNSEScripts = "*dns*"
            individualPortScannerWithNSEScripts(target, port, nmapOutputFile, nmapNSEScripts)

        case "79":
            caseDir = protocolDetected("Finger")
            nmapOutputFile = caseDir + "finger_scan"
            individualPortScanner(target, port, nmapOutputFile)
            
            msfArgs := []string{"msfconsole", "-q", "-x", fmt.Sprintf("use auxiliary/scanner/finger/finger_users;set rhost %s;run;exit", target)}
            runTool(msfArgs, caseDir)

        case "80", "443", "8080": //TODO:
            if visitedHTTP { continue }
            visitedHTTP = true
            
            caseDir = protocolDetected("HTTP")
            nmapOutputFile = caseDir + "http_scan"
            individualPortScanner(target, "80,443,8080", nmapOutputFile)

        case "88":
            caseDir = protocolDetected("Kerberos")
            nmapOutputFile = caseDir + "kerberos_scan"
            individualPortScanner(target, port, nmapOutputFile)
            
            filePath = caseDir + "potential_DC_commands.txt"
            message := `Potential DC found. Enumerate further.
                        Get the name of the domain and chuck it to:
                        nmap -p 88 \ 
                        --script=krb5-enum-users \
                        --script-args krb5-enum-users.realm=\"{Domain_Name}\" \\\n,userdb={Big_Userlist} \\\n{IP}"`
            writeTextToFile(filePath, message)

        case "110", "143", "993", "995":
            if visitedIMAP { continue }
            visitedIMAP = true

            caseDir = protocolDetected("IMAP-POP3")
            nmapOutputFile = caseDir + "imap_pop3_scan"
            individualPortScanner(target, "110,143,993,995", nmapOutputFile)

            // Openssl
            openSSLArgs := []string{"openssl", "s_client", "-connect", fmt.Sprintf("%s:imaps", target)}
            runTool(openSSLArgs, caseDir)

            // NC banner grabbing
            ncArgs := []string{"nc", "-nv", target, port}
            runTool(ncArgs, caseDir)

        case "111": //TODO: implement UDP scan to catch RPC
            caseDir = protocolDetected("RPC")
            nmapOutputFile = caseDir + "rpc_scan"
            individualPortScanner(target, port, nmapOutputFile)

        case "113":
            caseDir = protocolDetected("Ident")
            nmapOutputFile = caseDir + "ident_scan"
            individualPortScanner(target, port, nmapOutputFile)
            
            // ident-user-enum
            spacedPorts := strings.Join(openPortsSlice, " ")
            identUserEnumArgs := []string{"ident-user-enum", target, spacedPorts}
            runTool(identUserEnumArgs, caseDir)

        case "135":
            caseDir = protocolDetected("MSRPC")
            nmapOutputFile = caseDir + "msrpc_scan"
            individualPortScanner(target, port, nmapOutputFile)

            rpcDumpArgs := []string{"rpcdump", port}
            runTool(prcDumpArgs, caseDir)

        case "137","138","139","445":
            // Run only once
            if visitedSMB { continue }
            visitedSMB = true
            caseDir = protocolDetected("NetBIOS-SMB")
            
            // Nmap
			nmapOutputFile = caseDir + "nb_smb_scan"
            nmapNSEScripts = "smb* and not brute"
            individualPortScannerWithNSEScripts(target, "137,139,445", nmapOutputFile, nsenmapNSEScripts) // TCP
            individualUDPPortScannerWithNSEScripts(target, "137", "nb_smb_UDP_scan", "nbstat.nse") // UDP
            
            // CME
            cmeArgs := []string{"crackmapexec", "smb", target}
            runTool(cmeArgs, caseDir)

            // CME BruteForcing
            cmeBfArgs := []string{"crackmapexec", "smb", "-u", usersList, "-p", darkwebTop1000, "--shares", "--sessions", "--disks", "--loggedon-users", "--users", "--groups", "--computers", "--local-groups", "--pass-pol", "--rid-brute", target}
            runTool(cmeBfArgs, caseDir)

            // SMBMap
            smbMapArgs := []string{"smbmap", "-H", target}
            runTool(smbMapArgs, caseDir)

            // NBLookup
            nbLookupArgs := []string{"nblookup", "-A", target}
            runTool(smbMapArgs, caseDir)

            // Enum4linux
            enum4linuxArgs := []string{"enum4linux", "-u", "''", "-p", "''", target}
            runTool(enum4linuxArgs, caseDir)

            // TODO: Remember to add enum4linux-ng to installs and here

        case "161","162","10161","10162": // UDP
            // TODO: (outstanding from AutoEnum) 
            // Hold on all SNMP enumeration until onesixtyone has finished bruteforcing community strings
            // then launch the tools in a loop against all the found CS
            if visitedSNMP { continue }
            visitedSNMP = true
            caseDir = protocolDetected("SNMP")

            // Nmap
            nmapOutputFile = caseDir + "snmp_scan"
            nmapNSEScripts = "snmp* and not snmp-brute"
            individualUDPPortScannerWithNSEScripts(target, "161,162,10161,10162", nmapOutputFile, nmapNSEScripts)

            // SNMPWalk
            snmpWalkArgs := []string{"snmpwalk", "-v2c", "-c", "public", target}
            runTool(snmpWalkArgs, caseDir)

            // OneSixtyOne
            oneSixtyOneArgs := []string{"onesixtyone", "-c", "$(locate SNMP/snmp.txt -l 1)", target}
            runTool(oneSixtyOneArgs, caseDir)

            // Braa
            // automate bf other CS than public
            braaArgs := []string{"braa", fmt.Sprintf("public@%s:.1.3.6.*", target)}
            runTool(braaArgs, caseDir)


        case "389","636","3268","3269":
            if visitedLDAP { continue }
            visitedLDAP = true
            caseDir = protocolDetected("LDAP")

            // Nmap
            nmapNSEScripts = "ldap* and not brute"
            individualPortScannerWithNSEScripts(target, "389,636,3268,3269", nmapOutputFile, nmapNSEScripts)

            // LDAPSearch
            ldapSearchArgs := []string{"ldapsearch", "-x", "-H", fmt.Sprintf("ldap://%s", target), "-D", "''", "-w", "''", "-b", "DC=<1_SUBDOMAIN>,DC=<TLD>"}
            runTool(ldapSearchArgs, caseDir)

        case "512","513","514":
            if visitedRsvc { continue }
            visitedRsvc = true
            caseDir = protocolDetected("RServices")

            // Nmap
            individualPortScanner(target, "512,513,514", nmapOutputFile)

            // Rwho
            rwhoArgs := []string{"rwho", "-a", target}
            runTool(rwhoArgs, caseDir)

            // Rusers
            rusersArgs := []string{"rusers", "-al", target}
            runtool(rusersArgs, caseDir)
            
            filePath := caseDir + "potential_DC_commands.txt"
            message = `Tip: Enumerate NFS, etc on the target server for /home/user/.rhosts and /etc/hosts.equiv files to use with rlogin, rsh and rexec.
                        If found, use the following command:
                        rlogin "target" -l "found_user"`
            writeTextToFile(filePath, message)

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