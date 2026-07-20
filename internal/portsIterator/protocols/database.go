package protocols

import (
	"fmt"

	"github.com/0x5ubt13/enumeraga/internal/checks"
	"github.com/0x5ubt13/enumeraga/internal/commands"
	"github.com/0x5ubt13/enumeraga/internal/portsIterator/common"
	"github.com/0x5ubt13/enumeraga/internal/utils"
)

// MySQL enumerates MySQL server (3306/TCP)
func MySQL(port string) {
	dir := utils.ProtocolDetected2("MYSQL", port, utils.BaseDir)

	// Nmap with NSE
	commands.CallIndividualPortScannerWithNSEScripts(utils.Target, port, dir+"mysql_scan_"+port, "mysql-* and not (brute or fuzzer or dos)", checks.OptVVerbose)

	// Nuclei
        nucleiArgs := []string{
                "nuclei",
                "-target", fmt.Sprintf("%s:%s", utils.Target, port),
                "-tags", "mysql",
                "-timeout", common.GetTimeoutSeconds(),
        }
        nucleiPath := fmt.Sprintf("%snuclei_%s.out", dir,port)
        commands.CallRunTool(nucleiArgs, nucleiPath, checks.OptVVerbose)

	// Hydra
	common.RunHydraBrute("mysql", dir)
}

// MSSQL enumerates Microsoft's SQL Server (1433/TCP)
func MSSQL(port string) {
	dir := utils.ProtocolDetected2("MSSQL",port ,utils.BaseDir)

	// Nmap with NSE
	nmapOutputFile := dir + "mssql_scan_" + port
	nmapNSEScripts := "ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes"
	nmapNSEScriptsArgs := map[string]string{
		"mssql.instance-port": port,
		"mssql.username":      "sa",
		"mssql.password":      "",
		"mssql.instance-name": "MSSQLSERVER",
	}
	commands.CallIndividualPortScannerWithNSEScriptsAndScriptArgs(utils.Target, port, nmapOutputFile, nmapNSEScripts, nmapNSEScriptsArgs, checks.OptVVerbose)

	// netexec brute
	if *checks.OptBrute {
		bruteCMEArgs := []string{"netexec", "mssql", utils.Target, "-u", utils.UsersList, "-p", utils.DarkwebTop1000}
		bruteCMEPath := fmt.Sprintf("%snetexec_brute.out", dir)
		commands.CallRunTool(bruteCMEArgs, bruteCMEPath, checks.OptVVerbose)
	}
}

// TNS enumerates Oracle's Transparent Network Substrate (1521/TCP)
func TNS(port string) {
	dir := utils.ProtocolDetected2("TNS", port, utils.BaseDir)
	nmapOutputFile := dir + "tns_scan_" + port
	nmapNSEScripts := "oracle-tns-version,oracle-sid-brute"
	commands.CallIndividualPortScannerWithNSEScripts(utils.Target, port, nmapOutputFile, nmapNSEScripts, checks.OptVVerbose)

	// Nuclei
        nucleiArgs := []string{
                "nuclei",
                "-target", fmt.Sprintf("%s:%s", utils.Target, port),
                "-tags", "oracle",
                "-timeout", common.GetTimeoutSeconds(),
        }
        nucleiPath := fmt.Sprintf("%snuclei_%s.out", dir,port)
        commands.CallRunTool(nucleiArgs, nucleiPath, checks.OptVVerbose)

	// ODAT - Oracle Database Attacking Tool
	odatArgs := []string{"odat", "all", "-s", utils.Target, "-p", port}
	odatPath := fmt.Sprintf("%sodat_%s.out", dir, port)
	commands.CallRunTool(odatArgs, odatPath, checks.OptVVerbose)
}
