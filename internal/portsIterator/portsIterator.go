package portsIterator

import (
	"fmt"
	"strings"

	"github.com/0x5ubt13/enumeraga/internal/commands"
	"github.com/0x5ubt13/enumeraga/internal/utils"
)

// Core functionality of the script
// Iterate through each port and automate launching tools
func Run(target string, baseDir string, openPortsSlice []string) {
	var (
		msfArgs, hydraArgs []string
		caseDir, filePath, message, nmapOutputFile,
		nmapNSEScripts, hydraPath, msfPath string
		visitedFTP, visitedSMTP, visitedHTTP, visitedIMAP,
		visitedSMB, visitedSNMP, visitedLDAP, visitedRsvc, visitedWinRM bool
	)

	// Bruteforce flag?
	if *utils.OptBrute {
		if !*utils.OptQuiet {
			fmt.Printf("%s\n",
				utils.Cyan("[*] Bruteforce flag detected. Activating fuzzing and bruteforcing tools where applicable."))
			utils.GetWordlists()
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

			caseDir = utils.ProtocolDetected("FTP", baseDir)
			nmapOutputFile = caseDir + "ftp_scan"
			nmapNSEScripts = "ftp-* and not brute"
			commands.CallIndividualPortScannerWithNSEScripts(target, "20,21", nmapOutputFile, nmapNSEScripts)

			// Hydra for FTP
			if *utils.OptBrute {
				hydraArgs = []string{"hydra", "-L", utils.UsersList, "-P", utils.DarkwebTop1000, "-f", fmt.Sprintf("%s://%s", "ftp", target)}
				hydraPath = fmt.Sprintf("%shydra_ftp.out", caseDir)
				commands.CallRunTool(hydraArgs, hydraPath)
			}

		case "22":
			caseDir = utils.ProtocolDetected("SSH", baseDir)
			nmapOutputFile = caseDir + "ssh_scan"
			nmapNSEScripts = "ssh-* and not brute"
			commands.CallIndividualPortScannerWithNSEScripts(target, port, nmapOutputFile, nmapNSEScripts)

			// Hydra for SSH
			if *utils.OptBrute {
				hydraArgs = []string{"hydra", "-L", utils.UsersList, "-P", utils.DarkwebTop1000, "-f", fmt.Sprintf("%s://%s", "ssh", target)}
				hydraPath = fmt.Sprintf("%shydra_ssh.out", caseDir)
				commands.CallRunTool(hydraArgs, hydraPath)
			}

		case "25", "465", "587":
			if visitedSMTP {
				continue
			}
			visitedSMTP = true

			caseDir = utils.ProtocolDetected("SMTP", baseDir)
			nmapOutputFile = caseDir + "smtp_scan"
			nmapNSEScripts = "smtp-commands,smtp-enum-users,smtp-open-relay"
			commands.CallIndividualPortScannerWithNSEScripts(target, "25,465,587", nmapOutputFile, nmapNSEScripts)

		case "53":
			caseDir = utils.ProtocolDetected("DNS", baseDir)
			nmapOutputFile = caseDir + "dns_scan"
			nmapNSEScripts = "*dns*"
			commands.CallIndividualPortScannerWithNSEScripts(target, port, nmapOutputFile, nmapNSEScripts)

		case "79":
			caseDir = utils.ProtocolDetected("Finger", baseDir)
			nmapOutputFile = caseDir + "finger_scan"
			commands.CallIndividualPortScanner(target, port, nmapOutputFile)

			msfArgs = []string{"msfconsole", "-q", "-x", fmt.Sprintf("use auxiliary/scanner/finger/finger_users;set rhost %s;run;exit", target)}
			msfPath = fmt.Sprintf("%smsfconsole.out", caseDir)
			commands.CallRunTool(msfArgs, msfPath)

		case "80", "443", "8080":
			if visitedHTTP {
				continue
			}
			visitedHTTP = true

			caseDir = utils.ProtocolDetected("HTTP", baseDir)
			nmapOutputFile = caseDir + "http_scan"
			commands.CallIndividualPortScanner(target, "80,443,8080", nmapOutputFile)

			// Port 80:

			// WordPress on port 80
			commands.WPEnumeration(fmt.Sprintf("https://%s:80", target), caseDir, "80")

			// Nikto on port 80
			nikto80Args := []string{"nikto", "-host", fmt.Sprintf("http://%s:80", target)}
			nikto80Path := fmt.Sprintf("%snikto_80.out", caseDir)
			commands.CallRunTool(nikto80Args, nikto80Path)

			// Wafw00f on port 80
			wafw00f80Args := []string{"wafw00f", "-v", fmt.Sprintf("http://%s:80", target)}
			wafw00f80Path := fmt.Sprintf("%swafw00f_80.out", caseDir)
			commands.CallRunTool(wafw00f80Args, wafw00f80Path)

			// WhatWeb on port 80
			whatWeb80Args := []string{"whatweb", "-a", "3", "-v", fmt.Sprintf("http://%s:80", target)}
			whatWeb80Path := fmt.Sprintf("%swhatweb_80.out", caseDir)
			commands.CallRunTool(whatWeb80Args, whatWeb80Path)

			// Dirsearch - Light dirbusting on port 80
			dirsearch80Args := []string{"dirsearch", "-t", "10", "-u", fmt.Sprintf("http://%s", target)}
			dirsearch80Path := fmt.Sprintf("%sdirsearch_80.out", caseDir)
			commands.CallRunTool(dirsearch80Args, dirsearch80Path)

			if *utils.OptBrute {
				// TODO: check why ffuf doesn't work
				// CeWL + Ffuf Keywords Bruteforcing
				commands.CallRunCewlandFfufKeywords(target, caseDir, "80")
				commands.CallRunCewlandFfufKeywords(target, caseDir, "443")
			}

			// Port 443:

			// WordPress on port 443
			commands.WPEnumeration(fmt.Sprintf("https://%s:443", target), caseDir, "443")

			// Nikto on port 443
			nikto443Args := []string{"nikto", "-host", fmt.Sprintf("https://%s:443", target)}
			nikto443Path := fmt.Sprintf("%snikto_443.out", caseDir)
			commands.CallRunTool(nikto443Args, nikto443Path)

			// Wafw00f on port 443
			wafw00f443Args := []string{"wafw00f", "-v", fmt.Sprintf("http://%s:443", target)}
			wafw00f443Path := fmt.Sprintf("%swafw00f_443.out", caseDir)
			commands.CallRunTool(wafw00f443Args, wafw00f443Path)

			// WhatWeb on port 443
			whatWeb443Args := []string{"whatweb", "-a", "3", "-v", fmt.Sprintf("http://%s:443", target)}
			whatWeb443Path := fmt.Sprintf("%swhatweb_443.out", caseDir)
			commands.CallRunTool(whatWeb443Args, whatWeb443Path)

			// Dirsearch - Light dirbusting on port 80
			dirsearch443Args := []string{"dirsearch", "-t", "10", "-u", fmt.Sprintf("https://%s", target)}
			dirsearch443Path := fmt.Sprintf("%sdirsearch_443.out", caseDir)
			commands.CallRunTool(dirsearch443Args, dirsearch443Path)

			// Port 8080

			// WordPress on port 8080
			commands.WPEnumeration(fmt.Sprintf("https://%s:8080", target), caseDir, "8080")

			// Tomcat
			commands.TomcatEnumeration(target, fmt.Sprintf("https://%s:8080/docs", target), caseDir, "8080")

		case "88":
			caseDir = utils.ProtocolDetected("Kerberos", baseDir)
			nmapOutputFile = caseDir + "kerberos_scan"
			commands.CallIndividualPortScanner(target, port, nmapOutputFile)

			filePath = caseDir + "potential_DC_commands.txt"
			message = `
            Potential DC found. Enumerate further.
            Get the name of the domain and chuck it to:
            nmap -p 88 \ 
            --script=krb5-enum-users \
            --script-args krb5-enum-users.realm=\"{Domain_Name}\" \\\n,userdb={Big_Userlist} \\\n{IP}"`
			utils.WriteTextToFile(filePath, message)

		case "110", "143", "993", "995":
			if visitedIMAP {
				continue
			}
			visitedIMAP = true

			caseDir = utils.ProtocolDetected("IMAP-POP3", baseDir)
			nmapOutputFile = caseDir + "imap_pop3_scan"
			commands.CallIndividualPortScanner(target, "110,143,993,995", nmapOutputFile)

			// Openssl
			openSSLArgs := []string{"openssl", "s_client", "-connect", fmt.Sprintf("%s:imaps", target)}
			openSSLPath := fmt.Sprintf("%sopenssl_imap.out", caseDir)
			commands.CallRunTool(openSSLArgs, openSSLPath)

			// NC banner grabbing
			ncArgs := []string{"nc", "-nv", target, port}
			ncPath := fmt.Sprintf("%sbanner_grab.out", caseDir)
			commands.CallRunTool(ncArgs, ncPath)

		case "111":
			caseDir = utils.ProtocolDetected("RPC", baseDir)
			nmapOutputFile = caseDir + "rpc_scan"
			commands.CallIndividualPortScanner(target, port, nmapOutputFile)

		case "113":
			caseDir = utils.ProtocolDetected("Ident", baseDir)
			nmapOutputFile = caseDir + "ident_scan"
			commands.CallIndividualPortScanner(target, port, nmapOutputFile)

			// ident-user-enum
			spacedPorts := strings.Join(openPortsSlice, " ")
			identUserEnumArgs := []string{"ident-user-enum", target, spacedPorts}
			identUserEnumPath := fmt.Sprintf("%sident-user-enum.out", caseDir)
			commands.CallRunTool(identUserEnumArgs, identUserEnumPath)

		case "135":
			caseDir = utils.ProtocolDetected("MSRPC", baseDir)
			nmapOutputFile = caseDir + "msrpc_scan"
			commands.CallIndividualPortScanner(target, port, nmapOutputFile)

			rpcDumpArgs := []string{"impacket-rpcdump", port}
			rpcDumpPath := fmt.Sprintf("%srpcdump.out", caseDir)
			commands.CallRunTool(rpcDumpArgs, rpcDumpPath)

		case "137", "138", "139", "445":
			// Run only once
			if visitedSMB {
				continue
			}
			visitedSMB = true
			caseDir = utils.ProtocolDetected("NetBIOS-SMB", baseDir)

			// Nmap
			nmapOutputFile = caseDir + "nb_smb_scan"
			nmapUDPOutputFile := caseDir + "nb_smb_UDP_scan"
			nmapNSEScripts = "smb* and not brute"
			commands.CallIndividualPortScannerWithNSEScripts(target, "137,139,445", nmapOutputFile, nmapNSEScripts) // TCP
			commands.CallIndividualUDPPortScannerWithNSEScripts(target, "137", nmapUDPOutputFile, "nbstat.nse")     // UDP

			// CME
			cmeArgs := []string{"crackmapexec", "smb", "-u", "''", "-p", "''", target}
			cmePath := fmt.Sprintf("%scme_anon.out", caseDir)
			commands.CallRunTool(cmeArgs, cmePath)

			if *utils.OptBrute {
				// CME BruteForcing
				cmeBfArgs := []string{"crackmapexec", "smb", "-u", utils.UsersList, "-p", utils.DarkwebTop1000, "--shares", "--sessions", "--disks", "--loggedon-users", "--users", "--groups", "--computers", "--local-groups", "--pass-pol", "--rid-brute", target}
				cmeBfPath := fmt.Sprintf("%scme_bf.out", caseDir)
				commands.CallRunTool(cmeBfArgs, cmeBfPath)
			}

			// SMBMap
			smbMapArgs := []string{"smbmap", "-H", target}
			smbMapPath := fmt.Sprintf("%ssmbmap.out", caseDir)
			commands.CallRunTool(smbMapArgs, smbMapPath)

			// NMBLookup
			nmbLookupArgs := []string{"nmblookup", "-A", target}
			nmbLookupPath := fmt.Sprintf("%snmblookup.out", caseDir)
			commands.CallRunTool(nmbLookupArgs, nmbLookupPath)

			// Enum4linux-ng
			enum4linuxNgArgs := []string{"enum4linux-ng", "-A", "-C", target}
			enum4linuxNgPath := fmt.Sprintf("%senum4linux_ng.out", caseDir)
			commands.CallRunTool(enum4linuxNgArgs, enum4linuxNgPath)

		case "161", "162", "10161", "10162": // UDP
			utils.GetWordlists()

			// TODO: (outstanding from AutoEnum)
			// Hold on all SNMP enumeration until onesixtyone has finished bruteforcing community strings
			// then launch the tools in a loop against all the found CS
			if visitedSNMP {
				continue
			}
			visitedSNMP = true
			caseDir = utils.ProtocolDetected("SNMP", baseDir)

			// Nmap
			nmapOutputFile = caseDir + "snmp_scan"
			nmapNSEScripts = "snmp* and not snmp-brute"
			commands.CallIndividualUDPPortScannerWithNSEScripts(target, "161,162,10161,10162", nmapOutputFile, nmapNSEScripts)

			// SNMPWalk
			snmpWalkArgs := []string{"snmpwalk", "-v2c", "-c", "public", target}
			snmpWalkPath := fmt.Sprintf("%ssnmpwalk_v2c_public.out", caseDir)
			commands.CallRunTool(snmpWalkArgs, snmpWalkPath)

			// OneSixtyOne
			oneSixtyOneArgs := []string{"onesixtyone", "-c", utils.SnmpList, target}
			oneSixtyOnePath := fmt.Sprintf("%snblookup.out", caseDir)
			commands.CallRunTool(oneSixtyOneArgs, oneSixtyOnePath)

			// Braa
			// automate bf other CS than public
			braaArgs := []string{"braa", fmt.Sprintf("public@%s:.1.3.6.*", target)}
			braaPath := fmt.Sprintf("%sbraa_public.out", caseDir)
			commands.CallRunTool(braaArgs, braaPath)

		case "389", "636", "3268", "3269":
			if visitedLDAP {
				continue
			}
			visitedLDAP = true
			caseDir = utils.ProtocolDetected("LDAP", baseDir)

			// Nmap
			nmapNSEScripts = "ldap* and not brute"
			commands.CallIndividualPortScannerWithNSEScripts(target, "389,636,3268,3269", nmapOutputFile, nmapNSEScripts)

			// LDAPSearch
			ldapSearchArgs := []string{"ldapsearch", "-x", "-H", fmt.Sprintf("ldap://%s", target), "-D", "''", "-w", "''", "-b", "DC=<1_SUBDOMAIN>,DC=<TLD>"}
			ldapSearchPath := fmt.Sprintf("%sldapsearch.out", caseDir)
			commands.CallRunTool(ldapSearchArgs, ldapSearchPath)

		case "512", "513", "514":
			if visitedRsvc {
				continue
			}
			visitedRsvc = true
			caseDir = utils.ProtocolDetected("RServices", baseDir)

			// Nmap
			commands.CallIndividualPortScanner(target, "512,513,514", nmapOutputFile)

			// Rwho
			rwhoArgs := []string{"rwho", "-a", target}
			rwhoPath := fmt.Sprintf("%srwho.out", caseDir)
			commands.CallRunTool(rwhoArgs, rwhoPath)

			// Rusers
			rusersArgs := []string{"rusers", "-la", target}
			rusersPath := fmt.Sprintf("%srusers.out", caseDir)
			commands.CallRunTool(rusersArgs, rusersPath)

			filePath = caseDir + "next_step_tip.txt"
			message = `
            Tip: Enumerate NFS, etc on the target server for /home/user/.rhosts and /etc/hosts.equiv files to use with rlogin, rsh and rexec.
            If found, use the following command:
            rlogin "target" -l "found_user"`
			utils.WriteTextToFile(filePath, message)

		case "623":
			caseDir = utils.ProtocolDetected("IPMI", baseDir)
			nmapOutputFile = caseDir + "ipmi_scan"

			// Nmap
			nmapNSEScripts = "ipmi*"
			commands.CallIndividualUDPPortScannerWithNSEScripts(target, port, nmapOutputFile, nmapNSEScripts)

			// Metasploit
			msfArgs = []string{"msfconsole", "-q", "-x", fmt.Sprintf("use auxiliary/scanner/ipmi/ipmi_dumphashes; set rhosts %s; set output_john_file %sipmi_hashes.john; run; exit", target, caseDir)}
			msfPath = fmt.Sprintf("%smsf_scanner.out", caseDir)
			commands.CallRunTool(msfArgs, msfPath)

		case "873":
			caseDir = utils.ProtocolDetected("Rsync", baseDir)
			nmapOutputFile = caseDir + "rsync_scan"
			commands.CallIndividualPortScanner(target, port, nmapOutputFile)

			// Netcat
			ncArgs := []string{"nc", "-nv", target, port}
			ncPath := fmt.Sprintf("%sbanner_grab.out", caseDir)
			commands.CallRunTool(ncArgs, ncPath)

			filePath = caseDir + "next_steps_tip.txt"
			message = `Tip: If nc's output has a drive in it after enumerating the version, for example 'dev', your natural following step should be:
            "rsync -av --list-only rsync://${target}/dev"`
			utils.WriteTextToFile(filePath, message)

		case "1433":
			caseDir = utils.ProtocolDetected("MSSQL", baseDir)
			nmapOutputFile = caseDir + "mssql"
			nmapNSEScripts = "ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes"
			nmapNSEScriptsArgs := map[string]string{
				"mssql.instance-port": "1433",
				"mssql.username":      "sa",
				"mssql.password":      "",
				"mssql.instance-name": "MSSQLSERVER",
			}
			commands.CallIndividualPortScannerWithNSEScriptsAndScriptArgs(target, port, nmapOutputFile, nmapNSEScripts, nmapNSEScriptsArgs)

			if *utils.OptBrute {
				bruteCMEArgs := []string{"crackmapexec", "mssql", target, "-u", utils.UsersList, "-p", utils.DarkwebTop1000}
				bruteCMEPath := fmt.Sprintf("%scme_brute.out", caseDir)
				commands.CallRunTool(bruteCMEArgs, bruteCMEPath)
			}

		case "1521":
			caseDir = utils.ProtocolDetected("TNS", baseDir)
			nmapOutputFile = caseDir + "tns_scan"
			nmapNSEScripts = "oracle-sid-brute"
			commands.CallIndividualPortScannerWithNSEScripts(target, port, nmapOutputFile, nmapNSEScripts)

			// TODO: Check executing this: odat all -s "${1}" >> "${tns_dir}odat.out" &&
			startSentence := "[!] Run this manually: '"
			midSentence := fmt.Sprintf("odat all --output-file %sodat.out -s %s", caseDir, target)
			utils.PrintCustomBiColourMsg("yellow", "cyan", startSentence, midSentence, "'")

		case "2049":
			caseDir = utils.ProtocolDetected("NFS", baseDir)
			nmapOutputFile = caseDir + "nfs_scan"
			nmapNSEScripts = "nfs-ls,nfs-showmount,nfs-statfs"
			commands.CallIndividualPortScannerWithNSEScripts(target, port, nmapOutputFile, nmapNSEScripts)

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
			caseDir = utils.ProtocolDetected("MYSQL", baseDir)
			nmapOutputFile = caseDir + "mysql_scan"
			nmapNSEScripts = "mysql*"
			commands.CallIndividualPortScannerWithNSEScripts(target, port, nmapOutputFile, nmapNSEScripts)

			// Hydra for MySQL
			if *utils.OptBrute {
				hydraArgs = []string{"hydra", "-L", utils.UsersList, "-P", utils.DarkwebTop1000, "-f", fmt.Sprintf("%s://%s", "mysql", target)}
				hydraPath = fmt.Sprintf("%shydra_mysql.out", caseDir)
				commands.CallRunTool(hydraArgs, hydraPath)
			}

		case "3389":
			caseDir = utils.ProtocolDetected("RDP", baseDir)
			nmapOutputFile = caseDir + "rdp_scan"
			nmapNSEScripts = "rdp*"
			commands.CallIndividualPortScannerWithNSEScripts(target, port, nmapOutputFile, nmapNSEScripts)

			// Hydra for RDP
			if *utils.OptBrute {
				hydraArgs = []string{"hydra", "-L", utils.UsersList, "-P", utils.DarkwebTop1000, "-f", fmt.Sprintf("%s://%s", "rdp", target)}
				hydraPath = fmt.Sprintf("%shydra_rdp.out", caseDir)
				commands.CallRunTool(hydraArgs, hydraPath)
			}

		case "5985", "5986":
			if visitedWinRM {
				continue
			}
			visitedWinRM = true

			caseDir = utils.ProtocolDetected("WinRM", baseDir)
			nmapOutputFile = caseDir + "winrm_scan"
			commands.CallIndividualPortScanner(target, "5985,5986", nmapOutputFile)

		case "10000":
			// TODO: if not webmin, enum ndmp.
			caseDir = utils.ProtocolDetected("webmin", baseDir)
			nmapOutputFile = caseDir + "webmin_scan"
			commands.CallIndividualPortScanner(target, port, nmapOutputFile)

		default:
			if *utils.OptVVervose {
				fmt.Printf("%s %s %s %s %s\n", utils.Red("[-] Port"), utils.Yellow(port), utils.Red("detected, but I don't know how to handle it yet. Please check the"), utils.Cyan("main Nmap"), utils.Red("scan"))
			}
		}
	}

	utils.PrintCustomBiColourMsg("green", "yellow", "[+] Done! All well-known ports included in Enumeraga for '", target, "' were successfully parsed.")
}
