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
	if *optDbg {
		fmt.Println("Debug - Start of portsIterator function")
		defer fmt.Println("Debug - End of portsIterator function")
	}

	var (
		msfArgs                                                                                                            []string
		caseDir, filePath, message, nmapOutputFile, nmapNSEScripts, msfPath                                                   string
		visitedFTP, visitedSMTP, visitedHTTP, visitedIMAP, visitedSMB, visitedSNMP, visitedLDAP, visitedRsvc, visitedWinRM bool
	)

	// DEV: Debugging purposes
	if *optDbg {
		fmt.Printf("%s %s\n", "Debug: baseDir: ", baseDir)
	}

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
			if visitedFTP {
				continue
			}
			visitedFTP = true

			caseDir = protocolDetected("FTP", baseDir)
			nmapOutputFile = caseDir + "ftp_scan"
			nmapNSEScripts = "ftp-* and not brute"
			callIndividualPortScannerWithNSEScripts(target, "20,21", nmapOutputFile, nmapNSEScripts)
			hydraBruteforcing(target, caseDir, "ftp")

		case "22":
			caseDir = protocolDetected("SSH", baseDir)
			nmapOutputFile = caseDir + "ssh_scan"
			nmapNSEScripts = "ssh-* and not brute"
			callIndividualPortScannerWithNSEScripts(target, port, nmapOutputFile, nmapNSEScripts)
			hydraBruteforcing(target, caseDir, "ssh")

		case "25", "465", "587":
			if visitedSMTP {
				continue
			}
			visitedHTTP = true

			caseDir = protocolDetected("SMTP", baseDir)
			nmapOutputFile = caseDir + "smtp_scan"
			nmapNSEScripts = "smtp-commands,smtp-enum-users,smtp-open-relay"
			callIndividualPortScannerWithNSEScripts(target, "25,465,587", nmapOutputFile, nmapNSEScripts)

		case "53":
			caseDir = protocolDetected("DNS", baseDir)
			nmapOutputFile = caseDir + "dns_scan"
			nmapNSEScripts = "*dns*"
			callIndividualPortScannerWithNSEScripts(target, port, nmapOutputFile, nmapNSEScripts)

		case "79":
			caseDir = protocolDetected("Finger", baseDir)
			nmapOutputFile = caseDir + "finger_scan"
			callIndividualPortScanner(target, port, nmapOutputFile)

			msfArgs = []string{"msfconsole", "-q", "-x", fmt.Sprintf("use auxiliary/scanner/finger/finger_users;set rhost %s;run;exit", target)}
			msfPath := fmt.Sprintf("%smsfconsole.out", caseDir)
			callRunTool(msfArgs, msfPath)

		case "80", "443", "8080": //TODO:
			if visitedHTTP {
				continue
			}
			visitedHTTP = true

			caseDir = protocolDetected("HTTP", baseDir)
			nmapOutputFile = caseDir + "http_scan"
			callIndividualPortScanner(target, "80,443,8080", nmapOutputFile)

			// Port 80:

			// Nikto on port 80
			nikto80Args := []string{"nikto", "-host", fmt.Sprintf("http://%s:80", target)}
			nikto80Path := fmt.Sprintf("%snikto_80.out", caseDir)
			callRunTool(nikto80Args, nikto80Path)

			// Wafw00f on port 80
			wafw00f80Args := []string{"wafw00f", "-v", fmt.Sprintf("http://%s:80", target)}
			wafw00f80Path := fmt.Sprintf("%swafw00f_80.out", caseDir)
			callRunTool(wafw00f80Args, wafw00f80Path)

			// WhatWeb on port 80
			whatWeb80Args := []string{"whatweb", "-a", "3", "-v", fmt.Sprintf("http://%s:80", target)}
			whatWeb80Path := fmt.Sprintf("%swhatweb_80.out", caseDir)
			callRunTool(whatWeb80Args, whatWeb80Path)

			// Ffuf
			if *optBrute {
				runCewlandffuf(target, caseDir, "80")
			}

		case "88":
			caseDir = protocolDetected("Kerberos", baseDir)
			nmapOutputFile = caseDir + "kerberos_scan"
			callIndividualPortScanner(target, port, nmapOutputFile)

			filePath = caseDir + "potential_DC_commands.txt"
			message = `
            Potential DC found. Enumerate further.
            Get the name of the domain and chuck it to:
            nmap -p 88 \ 
            --script=krb5-enum-users \
            --script-args krb5-enum-users.realm=\"{Domain_Name}\" \\\n,userdb={Big_Userlist} \\\n{IP}"`
			writeTextToFile(filePath, message)

		case "110", "143", "993", "995":
			if visitedIMAP {
				continue
			}
			visitedIMAP = true

			caseDir = protocolDetected("IMAP-POP3", baseDir)
			nmapOutputFile = caseDir + "imap_pop3_scan"
			callIndividualPortScanner(target, "110,143,993,995", nmapOutputFile)

			// Openssl
			openSSLArgs := []string{"openssl", "s_client", "-connect", fmt.Sprintf("%s:imaps", target)}
			openSSLPath := fmt.Sprintf("%sopenssl_imap.out", caseDir)
			callRunTool(openSSLArgs, openSSLPath)

			// NC banner grabbing
			ncArgs := []string{"nc", "-nv", target, port}
			ncPath := fmt.Sprintf("%sbanner_grab.out", caseDir)
			callRunTool(ncArgs, ncPath)

		case "111": //TODO: implement UDP scan to catch RPC
			caseDir = protocolDetected("RPC", baseDir)
			nmapOutputFile = caseDir + "rpc_scan"
			callIndividualPortScanner(target, port, nmapOutputFile)

		case "113":
			caseDir = protocolDetected("Ident", baseDir)
			nmapOutputFile = caseDir + "ident_scan"
			callIndividualPortScanner(target, port, nmapOutputFile)

			// ident-user-enum
			spacedPorts := strings.Join(openPortsSlice, " ")
			identUserEnumArgs := []string{"ident-user-enum", target, spacedPorts}
			identUserEnumPath := fmt.Sprintf("%sident-user-enum.out", caseDir)
			callRunTool(identUserEnumArgs, identUserEnumPath)

		case "135":
			caseDir = protocolDetected("MSRPC", baseDir)
			nmapOutputFile = caseDir + "msrpc_scan"
			callIndividualPortScanner(target, port, nmapOutputFile)

			rpcDumpArgs := []string{"rpcdump", port}
			rpcDumpPath := fmt.Sprintf("%srpcdump.out", caseDir)
			callRunTool(rpcDumpArgs, rpcDumpPath)

		case "137", "138", "139", "445":
			// Run only once
			if visitedSMB {
				continue
			}
			visitedSMB = true
			caseDir = protocolDetected("NetBIOS-SMB", baseDir)

			// Nmap
			nmapOutputFile = caseDir + "nb_smb_scan"
			nmapNSEScripts = "smb* and not brute"
			callIndividualPortScannerWithNSEScripts(target, "137,139,445", nmapOutputFile, nmapNSEScripts) // TCP
			callIndividualUDPPortScannerWithNSEScripts(target, "137", "nb_smb_UDP_scan", "nbstat.nse")     // UDP

			// CME
			cmeArgs := []string{"crackmapexec", "smb", "-u", "''", "-p", "''", target}
			cmePath := fmt.Sprintf("%scme_anon.out", caseDir)
			callRunTool(cmeArgs, cmePath)

			if *optBrute {
				// CME BruteForcing
				cmeBfArgs := []string{"crackmapexec", "smb", "-u", usersList, "-p", darkwebTop1000, "--shares", "--sessions", "--disks", "--loggedon-users", "--users", "--groups", "--computers", "--local-groups", "--pass-pol", "--rid-brute", target}
				cmeBfPath := fmt.Sprintf("%scme_bf.out", caseDir)
				callRunTool(cmeBfArgs, cmeBfPath)
			}

			// SMBMap
			smbMapArgs := []string{"smbmap", "-H", target}
			smbMapPath := fmt.Sprintf("%ssmbmap.out", caseDir)
			callRunTool(smbMapArgs, smbMapPath)

			// NBLookup
			nbLookupArgs := []string{"nblookup", "-A", target}
			nbLookupPath := fmt.Sprintf("%snblookup.out", caseDir)
			callRunTool(nbLookupArgs, nbLookupPath)

			// Enum4linux-ng
			enum4linuxNgArgs := []string{"enum4linux-ng", "-A", "-C", target}
			enum4linuxNgPath := fmt.Sprintf("%snblookup.out", caseDir)
			callRunTool(enum4linuxNgArgs, enum4linuxNgPath)

			// TODO: Remember to add enum4linux-ng to installs and here

		case "161", "162", "10161", "10162": // UDP
			// TODO: (outstanding from AutoEnum)
			// Hold on all SNMP enumeration until onesixtyone has finished bruteforcing community strings
			// then launch the tools in a loop against all the found CS
			if visitedSNMP {
				continue
			}
			visitedSNMP = true
			caseDir = protocolDetected("SNMP", baseDir)

			// Nmap
			nmapOutputFile = caseDir + "snmp_scan"
			nmapNSEScripts = "snmp* and not snmp-brute"
			callIndividualUDPPortScannerWithNSEScripts(target, "161,162,10161,10162", nmapOutputFile, nmapNSEScripts)

			// SNMPWalk
			snmpWalkArgs := []string{"snmpwalk", "-v2c", "-c", "public", target}
			snmpWalkPath := fmt.Sprintf("%ssnmpwalk_v2c_public.out", caseDir)
			callRunTool(snmpWalkArgs, snmpWalkPath)

			// OneSixtyOne
			oneSixtyOneArgs := []string{"onesixtyone", "-c", "$(locate SNMP/snmp.txt -l 1)", target}
			oneSixtyOnePath := fmt.Sprintf("%snblookup.out", caseDir)
			callRunTool(oneSixtyOneArgs, oneSixtyOnePath)

			// Braa
			// automate bf other CS than public
			braaArgs := []string{"braa", fmt.Sprintf("public@%s:.1.3.6.*", target)}
			braaPath := fmt.Sprintf("%sbraa_public.out", caseDir)
			callRunTool(braaArgs, braaPath)

		case "389", "636", "3268", "3269":
			if visitedLDAP {
				continue
			}
			visitedLDAP = true
			caseDir = protocolDetected("LDAP", baseDir)

			// Nmap
			nmapNSEScripts = "ldap* and not brute"
			callIndividualPortScannerWithNSEScripts(target, "389,636,3268,3269", nmapOutputFile, nmapNSEScripts)

			// LDAPSearch
			ldapSearchArgs := []string{"ldapsearch", "-x", "-H", fmt.Sprintf("ldap://%s", target), "-D", "''", "-w", "''", "-b", "DC=<1_SUBDOMAIN>,DC=<TLD>"}
			ldapSearchPath := fmt.Sprintf("%sldapsearch.out", caseDir)
			callRunTool(ldapSearchArgs, ldapSearchPath)

		case "512", "513", "514":
			if visitedRsvc {
				continue
			}
			visitedRsvc = true
			caseDir = protocolDetected("RServices", baseDir)

			// Nmap
			callIndividualPortScanner(target, "512,513,514", nmapOutputFile)

			// Rwho
			rwhoArgs := []string{"rwho", "-a", target}
			rwhoPath := fmt.Sprintf("%srwho.out", caseDir)
			callRunTool(rwhoArgs, rwhoPath)

			// Rusers
			rusersArgs := []string{"rusers", "-al", target}
			rusersPath := fmt.Sprintf("%snblookup.out", caseDir)
			callRunTool(rusersArgs, rusersPath)

			filePath = caseDir + "next_step_tip.txt"
			message = `
            Tip: Enumerate NFS, etc on the target server for /home/user/.rhosts and /etc/hosts.equiv files to use with rlogin, rsh and rexec.
            If found, use the following command:
            rlogin "target" -l "found_user"`
			writeTextToFile(filePath, message)

		case "623":
			caseDir = protocolDetected("IPMI", baseDir)
			nmapOutputFile = caseDir + "ipmi_scan"

			// Nmap
			nmapNSEScripts = "ipmi*"
			callIndividualPortScannerWithNSEScripts(target, port, nmapOutputFile, nmapNSEScripts)

			// Metasploit
			msfArgs = []string{"msfconsole", "-q", "-x", fmt.Sprintf("use auxiliary/scanner/ipmi/ipmi_dumphashes; set rhosts %s; set output_john_file %sipmi_hashes.john; run; exit", target, caseDir)}
			msfPath = fmt.Sprintf("%snblookup.out", caseDir)
			callRunTool(msfArgs, caseDir)

		case "873":
			caseDir = protocolDetected("Rsync", baseDir)
			nmapOutputFile = caseDir + "rsync_scan"
			callIndividualPortScanner(target, port, nmapOutputFile)

			// Netcat
			ncArgs := []string{"nc", "-nv", target, port}
			ncPath := fmt.Sprintf("%sbanner_grab.out", caseDir)
			callRunTool(ncArgs, ncPath)

			filePath = caseDir + "next_steps_tip.txt"
			message = `Tip: If nc's output has a drive in it after enumerating the version, for example 'dev', your natural following step should be:
            "rsync -av --list-only rsync://${target}/dev"`
			writeTextToFile(filePath, message)

		case "1433":
			caseDir = protocolDetected("MSSQL", baseDir)
			nmapOutputFile = caseDir + "mssql"
			nmapNSEScripts = "ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes"
			nmapNSEScriptsArgs := map[string]string{
				"mssql.instance-port": "1433",
				"mssql.username":      "sa",
				"mssql.password":      "",
				"mssql.instance-name": "MSSQLSERVER",
			}
			callIndividualPortScannerWithNSEScriptsAndScriptArgs(target, port, nmapOutputFile, nmapNSEScripts, nmapNSEScriptsArgs)

			if *optBrute {
				bruteCMEArgs := []string{"crackmapexec", "mssql", target, "-u", usersList, "-p", darkwebTop1000}
				bruteCMEPath := fmt.Sprintf("%scme_brute.out", caseDir)
				callRunTool(bruteCMEArgs, bruteCMEPath)
			}

		case "1521":
			caseDir = protocolDetected("TNS", baseDir)
			nmapOutputFile = caseDir + "tns_scan"
			nmapNSEScripts = "oracle-sid-brute"
			callIndividualPortScannerWithNSEScripts(target, port, nmapOutputFile, nmapNSEScripts)

			// TODO: Check executing this: odat all -s "${1}" >> "${tns_dir}odat.out" &&
			startSentence := "[!] Run this manually: '"
			midSentence := fmt.Sprintf("odat all --output-file %sodat.out -s %s", caseDir, target)
			printCustomBiColourMsg("yellow", "cyan", startSentence, midSentence, "'")

		case "2049":
			caseDir = protocolDetected("NFS", baseDir)
			nmapOutputFile = caseDir + "nfs_scan"
			nmapNSEScripts = "nfs-ls,nfs-showmount,nfs-statfs"
			callIndividualPortScannerWithNSEScripts(target, port, nmapOutputFile, nmapNSEScripts)

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
			caseDir = protocolDetected("MYSQL", baseDir)
			nmapOutputFile = caseDir + "mysql_scan"
			nmapNSEScripts = "mysql*"
			callIndividualPortScannerWithNSEScripts(target, port, nmapOutputFile, nmapNSEScripts)

			hydraBruteforcing(target, caseDir, "mysql")

		case "3389":
			caseDir = protocolDetected("RDP", baseDir)
			nmapOutputFile = caseDir + "rdp_scan"
			nmapNSEScripts = "rdp*"
			callIndividualPortScannerWithNSEScripts(target, port, nmapOutputFile, nmapNSEScripts)

			hydraBruteforcing(target, caseDir, "rdp")

		case "5985", "5986":
			if visitedWinRM {
				continue
			}
			visitedWinRM = true

			caseDir = protocolDetected("WinRM", baseDir)
			nmapOutputFile = caseDir + "winrm_scan"
			callIndividualPortScanner(target, "5985,5986", nmapOutputFile)

		case "10000":
			// TODO: if not webmin, enum ndmp.
			caseDir = protocolDetected("webmin", baseDir)
			nmapOutputFile = caseDir + "webmin_scan"
			callIndividualPortScanner(target, port, nmapOutputFile)

		default:
			if *optVVervose {
				fmt.Printf("%s %s %s %s %s\n", red("[-] Port"), yellow(port), red("detected, but I don't know how to handle it yet. Please check the"), cyan("main Nmap"), red("scan"))
			}
		}
	}

	printCustomBiColourMsg("green", "yellow", "[+] Done! All well-known ports included in Enumeraga for '", target, "' were successfully parsed.")

}
