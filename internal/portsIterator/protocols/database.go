package protocols

import (
	"fmt"

	"github.com/0x5ubt13/enumeraga/internal/checks"
	"github.com/0x5ubt13/enumeraga/internal/commands"
	"github.com/0x5ubt13/enumeraga/internal/portsIterator/common"
	"github.com/0x5ubt13/enumeraga/internal/utils"
)

// MySQL enumerates MySQL server (3306/TCP)
func MySQL() {
	dir := utils.ProtocolDetected("MYSQL", utils.BaseDir)
	commands.CallIndividualPortScannerWithNSEScripts(utils.Target, "3306", dir+"mysql_scan", "mysql*", checks.OptVVerbose)
	common.RunHydraBrute("mysql", dir)
}

// MSSQL enumerates Microsoft's SQL Server (1433/TCP)
func MSSQL() {
	dir := utils.ProtocolDetected("MSSQL", utils.BaseDir)
	nmapOutputFile := dir + "mssql"
	nmapNSEScripts := "ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes"
	nmapNSEScriptsArgs := map[string]string{
		"mssql.instance-port": "1433",
		"mssql.username":      "sa",
		"mssql.password":      "",
		"mssql.instance-name": "MSSQLSERVER",
	}
	commands.CallIndividualPortScannerWithNSEScriptsAndScriptArgs(utils.Target, "1433", nmapOutputFile, nmapNSEScripts, nmapNSEScriptsArgs, checks.OptVVerbose)

	if *checks.OptBrute {
		bruteCMEArgs := []string{"crackmapexec", "mssql", utils.Target, "-u", utils.UsersList, "-p", utils.DarkwebTop1000}
		bruteCMEPath := fmt.Sprintf("%scme_brute.out", dir)
		commands.CallRunTool(bruteCMEArgs, bruteCMEPath, checks.OptVVerbose)
	}
}

// TNS enumerates Oracle's Transparent Network Substrate (1521/TCP)
func TNS() {
	dir := utils.ProtocolDetected("TNS", utils.BaseDir)
	nmapOutputFile := dir + "tns_scan"
	nmapNSEScripts := "oracle-sid-brute"
	commands.CallIndividualPortScannerWithNSEScripts(utils.Target, "1521", nmapOutputFile, nmapNSEScripts, checks.OptVVerbose)

	// ODAT - Oracle Database Attacking Tool
	if utils.CheckToolExists("odat") {
		odatArgs := []string{"odat", "all", "-s", utils.Target}
		odatPath := fmt.Sprintf("%sodat.out", dir)
		commands.CallRunTool(odatArgs, odatPath, checks.OptVVerbose)
	} else {
		// Provide manual command if odat not installed
		startSentence := "[!] ODAT not found. Run this manually: '"
		midSentence := fmt.Sprintf("odat all --output-file %sodat.out -s %s", dir, utils.Target)
		utils.PrintCustomBiColourMsg("yellow", "cyan", startSentence, midSentence, "'")
	}
}
