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
        msfArgs []string
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
    }

    // Loop through every port
    for _, port := range openPortsSlice {
		switch port {
		case "20", "21":
            if visitedFTP { continue }
            visitedFTP = true

			caseDir = protocolDetected("FTP")
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
            
            msfArgs = []string{"msfconsole", "-q", "-x", fmt.Sprintf("use auxiliary/scanner/finger/finger_users;set rhost %s;run;exit", target)}
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
            message  = `
            Potential DC found. Enumerate further.
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
            runTool(rpcDumpArgs, caseDir)

        case "137","138","139","445":
            // Run only once
            if visitedSMB { continue }
            visitedSMB = true
            caseDir = protocolDetected("NetBIOS-SMB")
            
            // Nmap
			nmapOutputFile = caseDir + "nb_smb_scan"
            nmapNSEScripts = "smb* and not brute"
            individualPortScannerWithNSEScripts(target, "137,139,445", nmapOutputFile, nmapNSEScripts) // TCP
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
            runTool(nbLookupArgs, caseDir)

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
            runTool(rusersArgs, caseDir)
            
            filePath = caseDir + "next_step_tip.txt"
            message  = `
            Tip: Enumerate NFS, etc on the target server for /home/user/.rhosts and /etc/hosts.equiv files to use with rlogin, rsh and rexec.
            If found, use the following command:
            rlogin "target" -l "found_user"`
            writeTextToFile(filePath, message)

        case "623":
            caseDir = protocolDetected("IPMI")
            nmapOutputFile = caseDir + "ipmi_scan"

            // Nmap
            nmapNSEScripts = "ipmi*"
            individualPortScannerWithNSEScripts(target, port, nmapOutputFile, nmapNSEScripts)

            // Metasploit
            msfArgs = []string{"msfconsole", "-q", "-x", fmt.Sprintf("use auxiliary/scanner/ipmi/ipmi_dumphashes; set rhosts %s; set output_john_file %sipmi_hashes.john; run; exit", target, caseDir)}
            runTool(msfArgs, caseDir)

        case "873":
            caseDir = protocolDetected("Rsync")
            nmapOutputFile = caseDir + "rsync_scan"
            individualPortScanner(target, port, nmapOutputFile)

            // Netcat
            ncArgs := []string{"nc", "-nv", target, port}
            runTool(ncArgs, caseDir)

            filePath = caseDir + "next_steps_tip.txt"
            message  =  `Tip: If nc's output has a drive in it after enumerating the version, for example 'dev', your natural following step should be:
                        "rsync -av --list-only rsync://${target}/dev"`
            writeTextToFile(filePath, message)

        case "1433":
            caseDir = protocolDetected("MSSQL")
            nmapOutputFile = caseDir + "mssql"
            nmapNSEScripts = "ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes"
            nmapNSEScriptsArgs := map[string]string{
                "mssql.instance-port": "1433",
                "mssql.username": "sa",
                "mssql.password": "",
                "mssql.instance-name": "MSSQLSERVER",
            }
            individualPortScannerWithNSEScriptsAndScriptArgs(target, port, nmapOutputFile, nmapNSEScripts, nmapNSEScriptsArgs)

            if *optBrute {
                bruteCMEArgs := []string{"crackmapexec", "smb", target, "-u", usersList, "-p", darkwebTop1000}
                runTool(bruteCMEArgs, caseDir)
            }

        case "1521":
            caseDir = protocolDetected("TNS")
            nmapOutputFile = caseDir + "tns_scan"
            nmapNSEScripts = "oracle-sid-brute"
            individualPortScannerWithNSEScripts(target, port, nmapOutputFile, nmapNSEScripts)
            
            // TODO: Check executing this: odat all -s "${1}" >> "${tns_dir}odat.out" && 
            startSentence := "[!] Run this manually: '"
            midSentence := fmt.Sprintf("odat all --output-file %sodat.out -s %s", caseDir, target)
            printCustomTripleMsg("yellow", "cyan", startSentence, midSentence, "'")
        
        case "2049":
            caseDir = protocolDetected("NFS")
            nmapOutputFile = caseDir + "nfs_scan"
            nmapNSEScripts = "nfs-ls,nfs-showmount,nfs-statfs"
            individualPortScannerWithNSEScripts(target, port, nmapOutputFile, nmapNSEScripts)
            
            // TODO: port code for showmount + mount:
            // running_tool "Showmount + mount"
            // showmount -e "${1}" >> "${nfs_dir}"showmount.out 2>&1 && \
            // custom_mkdir "${nfs_dir}"mounted_NFS_contents/ && \
            // # While loop to mount every found drive with showmount:
            // grep "/" < "${nfs_dir}"showmount.out | cut -d " " -f1 | while IFS= read -r dir_to_mount
            // do
            //     custom_mkdir "${nfs_dir}mounted_NFS_contents/${dir_to_mount}/"
            //     mount -t nfs "${1}":/"${dir_to_mount}" "${nfs_dir}"mounted_NFS_contents/ -o nolock,vers=3,tcp,timeo=300 # TODO: check these mount options work fine
            // done && \
            // tree "${nfs_dir}"mounted_NFS_contents/ >> "${nfs_dir}nfs_mounts.tree" 2>&1 && \
            // finished_tool "Showmount + mount" "${1}" "${nfs_dir}showmount.out && cat ${nfs_dir}nfs_mounts.tree" && \
            // printf "To clean up and unmount the NFS drive, run 'umount -v '%s'/(mounted dirs)\n" "${nfs_dir}mounted_NFS_contents/" > "${nfs_dir}cleanup_readme.txt" &

        case "3306":
            caseDir = protocolDetected("MYSQL")
            nmapOutputFile = caseDir + "mysql_scan"
            nmapNSEScripts = "mysql*"
            individualPortScannerWithNSEScripts(target, port, nmapOutputFile, nmapNSEScripts)
            
            hydraBruteforcing(target, caseDir, "mysql")

        case "3389":
            caseDir = protocolDetected("RDP")
            nmapOutputFile = caseDir + "rdp_scan"
            nmapNSEScripts = "rdp*"
            individualPortScannerWithNSEScripts(target, port, nmapOutputFile, nmapNSEScripts)

            hydraBruteforcing(target, caseDir, "rdp")

        case "5985","5986":
            if visitedWinRM { continue }
            visitedWinRM = true

            caseDir = protocolDetected("WinRM")
            nmapOutputFile = caseDir + "winrm_scan"
            individualPortScanner(target, "5985,5986", nmapOutputFile)

        case "10000":
            // TODO: if not webmin, enum ndmp. 
            caseDir = protocolDetected("webmin")
            nmapOutputFile = caseDir + "webmin_scan"
            individualPortScanner(target, port, nmapOutputFile)

        default:
            if *optVVervose {fmt.Printf("%s %s %s %s %s\n", red("[-] Port"), yellow(port), red("detected, but I don't know how to handle it yet. Please check the"), cyan("main Nmap"), red("scan"))}
        }
	}
    
    printCustomTripleMsg("green", "yellow", "[+] Done! All well-known ports included in Enumeraga for", target, "were successfully parsed.")

}