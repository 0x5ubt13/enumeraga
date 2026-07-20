package protocols

import (
	"fmt"

	"github.com/0x5ubt13/enumeraga/internal/checks"
	"github.com/0x5ubt13/enumeraga/internal/commands"
	"github.com/0x5ubt13/enumeraga/internal/utils"
)

// LDAP enumerates Light Desktop Access Protocol (389,636,3268-3269/TCP)
func LDAP(port string, scheme string) {
	dir := utils.ProtocolDetected2("LDAP", port, utils.BaseDir)

	// nmap + nse
        commands.CallIndividualPortScannerWithNSEScripts(utils.Target, port, dir+"ldap_scan_"+port, "ldap* and not (brute or fuzzer or dos)", checks.OptVVerbose)

	// LDAPSearch - Anonymous bind to discover base DN
	ldapSearchArgs := []string{"ldapsearch", "-x", "-H", fmt.Sprintf("%s://%s:%s",scheme, utils.Target, port), "-s", "base", "-b", "", "defaultNamingContext"}
	ldapSearchPath := fmt.Sprintf("%sldapsearch_defaultNamingContext.out", dir)
	commands.CallRunTool(ldapSearchArgs, ldapSearchPath, checks.OptVVerbose)

	// LDAPSearch - Anonymous bind to get all users
	ldapSearchUsersArgs := []string{"ldapsearch", "-x", "-H", fmt.Sprintf("%s://%s:%s",scheme , utils.Target, port), "-b", "", "(objectClass=user)"}
	ldapSearchUsersPath := fmt.Sprintf("%sldapsearch_anonymous_users.out", dir)
	commands.CallRunTool(ldapSearchUsersArgs, ldapSearchUsersPath, checks.OptVVerbose)

	// LDAPSearch - Anonymous bind to enumerate everything (if allowed)
	ldapSearchFullArgs := []string{"ldapsearch", "-x", "-H", fmt.Sprintf("%s://%s:%s",scheme , utils.Target, port), "-b", ""}
	ldapSearchFullPath := fmt.Sprintf("%sldapsearch_anonymous_dump.out", dir)
	commands.CallRunTool(ldapSearchFullArgs, ldapSearchFullPath, checks.OptVVerbose)
}
// Kerberos enumerates Kerberos Protocol (88/TCP)
func Kerberos(port string) {
	dir := utils.ProtocolDetected2("Kerberos", port, utils.BaseDir)
	nmapOutputFile := dir + "kerberos_scan_" + port 
	commands.CallIndividualPortScanner(utils.Target, port, nmapOutputFile, checks.OptVVerbose)

}
