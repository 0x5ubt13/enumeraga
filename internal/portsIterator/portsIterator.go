package portsIterator

import (
	"fmt"
	"strings"

	"github.com/0x5ubt13/enumeraga/internal/commands"
	"github.com/0x5ubt13/enumeraga/internal/utils"
)

// Enumerate FTP
func ftp() {
	if utils.VisitedFTP {
		return
	}
	utils.VisitedFTP = true

	ftpDir := utils.ProtocolDetected("FTP", utils.BaseDir)
	nmapOutputFile := ftpDir + "ftp_scan"
	nmapNSEScripts := "ftp-* and not brute"
	commands.CallIndividualPortScannerWithNSEScripts(utils.Target, "20,21", nmapOutputFile, nmapNSEScripts)

	// Hydra for FTP
	if *utils.OptBrute {
		hydraArgs := []string{"hydra", "-L", utils.UsersList, "-P", utils.DarkwebTop1000, "-f", fmt.Sprintf("%s://%s", "ftp", utils.Target)}
		hydraPath := fmt.Sprintf("%shydra_ftp.out", ftpDir)
		commands.CallRunTool(hydraArgs, hydraPath)
	}
}

func ssh() {
	sshDir := utils.ProtocolDetected("SSH", utils.BaseDir)
	nmapOutputFile := sshDir + "ssh_scan"
	nmapNSEScripts := "ssh-* and not brute"
	commands.CallIndividualPortScannerWithNSEScripts(utils.Target, "22", nmapOutputFile, nmapNSEScripts)

	// Hydra for SSH
	if *utils.OptBrute {
		hydraArgs := []string{"hydra", "-L", utils.UsersList, "-P", utils.DarkwebTop1000, "-f", fmt.Sprintf("%s://%s", "ssh", utils.Target)}
		hydraPath := fmt.Sprintf("%shydra_ssh.out", sshDir)
		commands.CallRunTool(hydraArgs, hydraPath)
	}
}

func smtp() {
	if utils.VisitedSMTP {
		return
	}
	utils.VisitedSMTP = true

	dir := utils.ProtocolDetected("SMTP", utils.BaseDir)
	nmapOutputFile := dir + "smtp_scan"
	nmapNSEScripts := "smtp-commands,smtp-enum-users,smtp-open-relay"
	commands.CallIndividualPortScannerWithNSEScripts(utils.Target, "25,465,587", nmapOutputFile, nmapNSEScripts)
}

func dns() {
	dir := utils.ProtocolDetected("DNS", utils.BaseDir)
	nmapOutputFile := dir + "dns_scan"
	nmapNSEScripts := "*dns*"
	commands.CallIndividualPortScannerWithNSEScripts(utils.Target, "53", nmapOutputFile, nmapNSEScripts)
}

func finger() {
	dir := utils.ProtocolDetected("Finger", utils.BaseDir)
	nmapOutputFile := dir + "finger_scan"
	commands.CallIndividualPortScanner(utils.Target, "79", nmapOutputFile)

	msfArgs := []string{"msfconsole", "-q", "-x", fmt.Sprintf("use auxiliary/scanner/finger/finger_users;set rhost %s;run;exit", utils.Target)}
	msfPath := fmt.Sprintf("%smsfconsole.out", dir)
	commands.CallRunTool(msfArgs, msfPath)
}

func http() {
	if utils.VisitedHTTP {
		return
	}
	utils.VisitedHTTP = true

	dir := utils.ProtocolDetected("HTTP", utils.BaseDir)
	nmapOutputFile := dir + "http_scan"
	commands.CallIndividualPortScanner(utils.Target, "80,443,8080", nmapOutputFile)

	// Port 80:

	// WordPress on port 80
	commands.WPEnumeration(fmt.Sprintf("https://%s:80", utils.Target), dir, "80")

	// Nikto on port 80
	nikto80Args := []string{"nikto", "-host", fmt.Sprintf("http://%s:80", utils.Target)}
	nikto80Path := fmt.Sprintf("%snikto_80.out", dir)
	commands.CallRunTool(nikto80Args, nikto80Path)

	// Wafw00f on port 80
	wafw00f80Args := []string{"wafw00f", "-v", fmt.Sprintf("http://%s:80", utils.Target)}
	wafw00f80Path := fmt.Sprintf("%swafw00f_80.out", dir)
	commands.CallRunTool(wafw00f80Args, wafw00f80Path)

	// WhatWeb on port 80
	whatWeb80Args := []string{"whatweb", "-a", "3", "-v", fmt.Sprintf("http://%s:80", utils.Target)}
	whatWeb80Path := fmt.Sprintf("%swhatweb_80.out", dir)
	commands.CallRunTool(whatWeb80Args, whatWeb80Path)

	// Dirsearch - Light dirbusting on port 80
	dirsearch80Args := []string{"dirsearch", "-t", "10", "-u", fmt.Sprintf("http://%s", utils.Target)}
	dirsearch80Path := fmt.Sprintf("%sdirsearch_80.out", dir)
	commands.CallRunTool(dirsearch80Args, dirsearch80Path)

	if *utils.OptBrute {
		// TODO: check why ffuf doesn't work
		// CeWL + Ffuf Keywords Bruteforcing
		commands.CallRunCewlandFfufKeywords(utils.Target, dir, "80")
		commands.CallRunCewlandFfufKeywords(utils.Target, dir, "443")
	}

	// Port 443:

	// WordPress on port 443
	commands.WPEnumeration(fmt.Sprintf("https://%s:443", utils.Target), dir, "443")

	// Nikto on port 443
	nikto443Args := []string{"nikto", "-host", fmt.Sprintf("https://%s:443", utils.Target)}
	nikto443Path := fmt.Sprintf("%snikto_443.out", dir)
	commands.CallRunTool(nikto443Args, nikto443Path)

	// Wafw00f on port 443
	wafw00f443Args := []string{"wafw00f", "-v", fmt.Sprintf("http://%s:443", utils.Target)}
	wafw00f443Path := fmt.Sprintf("%swafw00f_443.out", dir)
	commands.CallRunTool(wafw00f443Args, wafw00f443Path)

	// WhatWeb on port 443
	whatWeb443Args := []string{"whatweb", "-a", "3", "-v", fmt.Sprintf("http://%s:443", utils.Target)}
	whatWeb443Path := fmt.Sprintf("%swhatweb_443.out", dir)
	commands.CallRunTool(whatWeb443Args, whatWeb443Path)

	// Dirsearch - Light dirbusting on port 80
	dirsearch443Args := []string{"dirsearch", "-t", "10", "-u", fmt.Sprintf("https://%s", utils.Target)}
	dirsearch443Path := fmt.Sprintf("%sdirsearch_443.out", dir)
	commands.CallRunTool(dirsearch443Args, dirsearch443Path)

	// Port 8080

	// WordPress on port 8080
	commands.WPEnumeration(fmt.Sprintf("https://%s:8080", utils.Target), dir, "8080")

	// Tomcat
	commands.TomcatEnumeration(utils.Target, fmt.Sprintf("https://%s:8080/docs", utils.Target), dir, "8080")
}

func kerberos() {
	dir := utils.ProtocolDetected("Kerberos", utils.BaseDir)
	nmapOutputFile := dir + "kerberos_scan"
	commands.CallIndividualPortScanner(utils.Target, "88", nmapOutputFile)

	filePath := dir + "potential_DC_commands.txt"
	message := `
	Potential DC found. Enumerate further.
	Get the name of the domain and chuck it to:
	nmap -p 88 \ 
	--script=krb5-enum-users \
	--script-args krb5-enum-users.realm=\"{Domain_Name}\" \\\n,userdb={Big_Userlist} \\\n{IP}"`
	utils.WriteTextToFile(filePath, message)
}

func imap() {
	if utils.VisitedIMAP {
		return
	}
	utils.VisitedIMAP = true

	dir := utils.ProtocolDetected("IMAP-POP3", utils.BaseDir)
	nmapOutputFile := dir + "imap_pop3_scan"
	commands.CallIndividualPortScanner(utils.Target, "110,143,993,995", nmapOutputFile)

	// Openssl
	openSSLArgs := []string{"openssl", "s_client", "-connect", fmt.Sprintf("%s:imaps", utils.Target)}
	openSSLPath := fmt.Sprintf("%sopenssl_imap.out", dir)
	commands.CallRunTool(openSSLArgs, openSSLPath)

	// NC banner grabbing
	ports := []string{"110","143","993","995"}
	for port := range ports {
		ncArgs := []string{"nc", "-nv", utils.Target, ports[port]}
		ncPath := fmt.Sprintf("%s%s_banner_grab.out", dir, ports[port])
		commands.CallRunTool(ncArgs, ncPath)
	}
}

func rpc() {
	dir := utils.ProtocolDetected("RPC", utils.BaseDir)
	nmapOutputFile := dir + "rpc_scan"
	commands.CallIndividualPortScanner(utils.Target, "111", nmapOutputFile)
}

func ident(openPortsSlice []string) {
	dir := utils.ProtocolDetected("Ident", utils.BaseDir)
	nmapOutputFile := dir + "ident_scan"
	commands.CallIndividualPortScanner(utils.Target, "113", nmapOutputFile)

	// ident-user-enum
	spacedPorts := strings.Join(openPortsSlice, " ")
	identUserEnumArgs := []string{"ident-user-enum", utils.Target, spacedPorts}
	identUserEnumPath := fmt.Sprintf("%sident-user-enum.out", dir)
	commands.CallRunTool(identUserEnumArgs, identUserEnumPath)
}

func msrpc() {
	dir := utils.ProtocolDetected("MSRPC", utils.BaseDir)
	nmapOutputFile := dir + "msrpc_scan"
	commands.CallIndividualPortScanner(utils.Target, "135", nmapOutputFile)

	rpcDumpArgs := []string{"impacket-rpcdump", "135"}
	rpcDumpPath := fmt.Sprintf("%srpcdump.out", dir)
	commands.CallRunTool(rpcDumpArgs, rpcDumpPath)
}

func smb() {
	if utils.VisitedSMB {
		return
	}
	utils.VisitedSMB = true
	dir := utils.ProtocolDetected("NetBIOS-SMB", utils.BaseDir)

	// Nmap
	nmapOutputFile := dir + "nb_smb_scan"
	nmapUDPOutputFile := dir + "nb_smb_UDP_scan"
	nmapNSEScripts := "smb* and not brute"
	commands.CallIndividualPortScannerWithNSEScripts(utils.Target, "137,139,445", nmapOutputFile, nmapNSEScripts) // TCP
	commands.CallIndividualUDPPortScannerWithNSEScripts(utils.Target, "137", nmapUDPOutputFile, "nbstat.nse")     // UDP

	// CME
	cmeArgs := []string{"crackmapexec", "smb", "-u", "''", "-p", "''", utils.Target}
	cmePath := fmt.Sprintf("%scme_anon.out", dir)
	commands.CallRunTool(cmeArgs, cmePath)

	if *utils.OptBrute {
		// CME BruteForcing
		cmeBfArgs := []string{"crackmapexec", "smb", "-u", utils.UsersList, "-p", utils.DarkwebTop1000, "--shares", "--sessions", "--disks", "--loggedon-users", "--users", "--groups", "--computers", "--local-groups", "--pass-pol", "--rid-brute", utils.Target}
		cmeBfPath := fmt.Sprintf("%scme_bf.out", dir)
		commands.CallRunTool(cmeBfArgs, cmeBfPath)
	}

	// SMBMap
	smbMapArgs := []string{"smbmap", "-H", utils.Target}
	smbMapPath := fmt.Sprintf("%ssmbmap.out", dir)
	commands.CallRunTool(smbMapArgs, smbMapPath)

	// NMBLookup
	nmbLookupArgs := []string{"nmblookup", "-A", utils.Target}
	nmbLookupPath := fmt.Sprintf("%snmblookup.out", dir)
	commands.CallRunTool(nmbLookupArgs, nmbLookupPath)

	// Enum4linux-ng
	enum4linuxNgArgs := []string{"enum4linux-ng", "-A", "-C", utils.Target}
	enum4linuxNgPath := fmt.Sprintf("%senum4linux_ng.out", dir)
	commands.CallRunTool(enum4linuxNgArgs, enum4linuxNgPath)
}

func snmp() {
	// TODO: (outstanding from AutoEnum)
	// Hold on all SNMP enumeration until onesixtyone has finished bruteforcing community strings
	// then launch the tools in a loop against all the found CS
	if utils.VisitedSNMP {
		return
	}
	utils.VisitedSNMP = true
	dir := utils.ProtocolDetected("SNMP", utils.BaseDir)

	// Nmap
	nmapOutputFile := dir + "snmp_scan"
	nmapNSEScripts := "snmp* and not snmp-brute"
	commands.CallIndividualUDPPortScannerWithNSEScripts(utils.Target, "161,162,10161,10162", nmapOutputFile, nmapNSEScripts)

	// SNMPWalk
	snmpWalkArgs := []string{"snmpwalk", "-v2c", "-c", "public", utils.Target}
	snmpWalkPath := fmt.Sprintf("%ssnmpwalk_v2c_public.out", dir)
	commands.CallRunTool(snmpWalkArgs, snmpWalkPath)

	// OneSixtyOne
	oneSixtyOneArgs := []string{"onesixtyone", "-c", utils.SnmpList, utils.Target}
	oneSixtyOnePath := fmt.Sprintf("%snblookup.out", dir)
	commands.CallRunTool(oneSixtyOneArgs, oneSixtyOnePath)

	// Braa
	// automate bf other CS than public
	braaArgs := []string{"braa", fmt.Sprintf("public@%s:.1.3.6.*", utils.Target)}
	braaPath := fmt.Sprintf("%sbraa_public.out", dir)
	commands.CallRunTool(braaArgs, braaPath)
}

func ldap() {
	if utils.VisitedLDAP {
		return
	}
	utils.VisitedLDAP = true
	dir := utils.ProtocolDetected("LDAP", utils.BaseDir)

	// Nmap
	nmapOutputFile := dir + "ldap_scan"
	nmapNSEScripts := "ldap* and not brute"
	commands.CallIndividualPortScannerWithNSEScripts(utils.Target, "389,636,3268,3269", nmapOutputFile, nmapNSEScripts)

	// LDAPSearch
	ldapSearchArgs := []string{"ldapsearch", "-x", "-H", fmt.Sprintf("ldap://%s", utils.Target), "-D", "''", "-w", "''", "-b", "DC=<1_SUBDOMAIN>,DC=<TLD>"}
	ldapSearchPath := fmt.Sprintf("%sldapsearch.out", dir)
	commands.CallRunTool(ldapSearchArgs, ldapSearchPath)
}

func rservices() {
	if utils.VisitedRsvc {
		return
	}
	utils.VisitedRsvc = true
	dir := utils.ProtocolDetected("RServices", utils.BaseDir)

	// Nmap
	nmapOutputFile := dir + "rservices_scan"
	commands.CallIndividualPortScanner(utils.Target, "512,513,514", nmapOutputFile)

	// Rwho
	rwhoArgs := []string{"rwho", "-a", utils.Target}
	rwhoPath := fmt.Sprintf("%srwho.out", dir)
	commands.CallRunTool(rwhoArgs, rwhoPath)

	// Rusers
	rusersArgs := []string{"rusers", "-la", utils.Target}
	rusersPath := fmt.Sprintf("%srusers.out", dir)
	commands.CallRunTool(rusersArgs, rusersPath)

	filePath := dir + "next_step_tip.txt"
	message := `
	Tip: Enumerate NFS, etc on the utils.Target server for /home/user/.rhosts and /etc/hosts.equiv files to use with rlogin, rsh and rexec.
	If found, use the following command:
	rlogin "utils.Target" -l "found_user"`
	utils.WriteTextToFile(filePath, message)
}

func ipmi() {
	dir := utils.ProtocolDetected("IPMI", utils.BaseDir)
	nmapOutputFile := dir + "ipmi_scan"

	// Nmap
	nmapNSEScripts := "ipmi*"
	commands.CallIndividualUDPPortScannerWithNSEScripts(utils.Target, "623", nmapOutputFile, nmapNSEScripts)

	// Metasploit
	msfArgs := []string{"msfconsole", "-q", "-x", fmt.Sprintf("use auxiliary/scanner/ipmi/ipmi_dumphashes; set rhosts %s; set output_john_file %sipmi_hashes.john; run; exit", utils.Target, dir)}
	msfPath := fmt.Sprintf("%smsf_scanner.out", dir)
	commands.CallRunTool(msfArgs, msfPath)
}

func rsync() {
	dir := utils.ProtocolDetected("Rsync", utils.BaseDir)
	nmapOutputFile := dir + "rsync_scan"
	commands.CallIndividualPortScanner(utils.Target, "623", nmapOutputFile)

	// Netcat
	ncArgs := []string{"nc", "-nv", utils.Target, "623"}
	ncPath := fmt.Sprintf("%sbanner_grab.out", dir)
	commands.CallRunTool(ncArgs, ncPath)

	filePath := dir + "next_steps_tip.txt"
	message := `Tip: If nc's output has a drive in it after enumerating the version, for example 'dev', your natural following step should be:
	"rsync -av --list-only rsync://${utils.Target}/dev"`
	utils.WriteTextToFile(filePath, message)
}

func mssql() {
	dir := utils.ProtocolDetected("MSSQL", utils.BaseDir)
	nmapOutputFile := dir + "mssql"
	nmapNSEScripts := "ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes"
	nmapNSEScriptsArgs := map[string]string{
		"mssql.instance-port": "1433",
		"mssql.username":      "sa",
		"mssql.password":      "",
		"mssql.instance-name": "MSSQLSERVER",
	}
	commands.CallIndividualPortScannerWithNSEScriptsAndScriptArgs(utils.Target, "1433", nmapOutputFile, nmapNSEScripts, nmapNSEScriptsArgs)

	if *utils.OptBrute {
		bruteCMEArgs := []string{"crackmapexec", "mssql", utils.Target, "-u", utils.UsersList, "-p", utils.DarkwebTop1000}
		bruteCMEPath := fmt.Sprintf("%scme_brute.out", dir)
		commands.CallRunTool(bruteCMEArgs, bruteCMEPath)
	}
}

func tns() {
	dir := utils.ProtocolDetected("TNS", utils.BaseDir)
	nmapOutputFile := dir + "tns_scan"
	nmapNSEScripts := "oracle-sid-brute"
	commands.CallIndividualPortScannerWithNSEScripts(utils.Target, "1521", nmapOutputFile, nmapNSEScripts)

	// TODO: Check executing this: odat all -s "${1}" >> "${tns_dir}odat.out" &&
	startSentence := "[!] Run this manually: '"
	midSentence := fmt.Sprintf("odat all --output-file %sodat.out -s %s", dir, utils.Target)
	utils.PrintCustomBiColourMsg("yellow", "cyan", startSentence, midSentence, "'")
}

func nfs() {
	dir := utils.ProtocolDetected("NFS", utils.BaseDir)
	nmapOutputFile := dir + "nfs_scan"
	nmapNSEScripts := "nfs-ls,nfs-showmount,nfs-statfs"
	commands.CallIndividualPortScannerWithNSEScripts(utils.Target, "2049", nmapOutputFile, nmapNSEScripts)

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
}

func mysql() {
	dir := utils.ProtocolDetected("MYSQL", utils.BaseDir)
	nmapOutputFile := dir + "mysql_scan"
	nmapNSEScripts := "mysql*"
	commands.CallIndividualPortScannerWithNSEScripts(utils.Target, "3306", nmapOutputFile, nmapNSEScripts)

	// Hydra for MySQL
	if *utils.OptBrute {
		hydraArgs := []string{"hydra", "-L", utils.UsersList, "-P", utils.DarkwebTop1000, "-f", fmt.Sprintf("%s://%s", "mysql", utils.Target)}
		hydraPath := fmt.Sprintf("%shydra_mysql.out", dir)
		commands.CallRunTool(hydraArgs, hydraPath)
	}
}

func rdp() {
	dir := utils.ProtocolDetected("RDP", utils.BaseDir)
	nmapOutputFile := dir + "rdp_scan"
	nmapNSEScripts := "rdp*"
	commands.CallIndividualPortScannerWithNSEScripts(utils.Target, "3389", nmapOutputFile, nmapNSEScripts)

	// Hydra for RDP
	if *utils.OptBrute {
		hydraArgs := []string{"hydra", "-L", utils.UsersList, "-P", utils.DarkwebTop1000, "-f", fmt.Sprintf("%s://%s", "rdp", utils.Target)}
		hydraPath := fmt.Sprintf("%shydra_rdp.out", dir)
		commands.CallRunTool(hydraArgs, hydraPath)
	}
}

func winrm() {
	if utils.VisitedWinRM {
		return
	}
	utils.VisitedWinRM = true

	dir := utils.ProtocolDetected("WinRM", utils.BaseDir)
	nmapOutputFile := dir + "winrm_scan"
	commands.CallIndividualPortScanner(utils.Target, "5985,5986", nmapOutputFile)
}

func tenthousand() {
	// TODO: if not webmin, enum ndmp.
	dir := utils.ProtocolDetected("webmin", utils.BaseDir)
	nmapOutputFile := dir + "webmin_scan"
	commands.CallIndividualPortScanner(utils.Target, "10000", nmapOutputFile)
}

// Iterate through each port, group up by protocol and automate launching tools
func Run(openPortsSlice []string) {
	for _, port := range openPortsSlice {
		switch port {
		case "20", "21":
			ftp()
		case "22":
			ssh()
		case "25", "465", "587":
			smtp()
		case "53":
			dns()
		case "79":
			finger()
		case "80", "443", "8080":
			http()
		case "88":
			kerberos()
		case "110", "143", "993", "995":
			imap()
		case "111":
			rpc()
		case "113":
			ident(openPortsSlice)
		case "135":
			msrpc()
		case "137", "138", "139", "445":
			smb()
		case "161", "162", "10161", "10162": // UDP
			snmp()
		case "389", "636", "3268", "3269":
			ldap()
		case "512", "513", "514":
			rservices()
		case "623":
			ipmi()
		case "873":
			rsync()
		case "1433":
			mssql()
		case "1521":
			tns()
		case "2049":
			nfs()
		case "3306":
			mysql()
		case "3389":
			rdp()
		case "5985", "5986":
			winrm()
		case "10000":
			tenthousand()
		default:
			if *utils.OptVVervose {
				fmt.Printf("%s %s %s %s %s\n", utils.Red("[-] Port"), utils.Yellow(port), utils.Red("detected, but I don't know how to handle it yet. Please check the"), utils.Cyan("main Nmap"), utils.Red("scan"))
			}
		}
	}
}
