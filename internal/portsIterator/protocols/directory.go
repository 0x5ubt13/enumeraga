package protocols

import (
	"fmt"

	"github.com/0x5ubt13/enumeraga/internal/checks"
	"github.com/0x5ubt13/enumeraga/internal/commands"
	"github.com/0x5ubt13/enumeraga/internal/utils"
)

// LDAP enumerates Light Desktop Access Protocol (389,636,3268-3269/TCP)
func LDAP() {
	if utils.IsVisited("ldap") {
		return
	}
	dir := utils.ProtocolDetected("LDAP", utils.BaseDir)

	// Nmap
	nmapOutputFile := dir + "ldap_scan"
	nmapNSEScripts := "ldap* and not brute"
	commands.CallIndividualPortScannerWithNSEScripts(utils.Target, "389,636,3268,3269", nmapOutputFile, nmapNSEScripts, checks.OptVVerbose)

	// LDAPSearch - Anonymous bind to discover base DN
	ldapSearchArgs := []string{"ldapsearch", "-x", "-H", fmt.Sprintf("ldap://%s", utils.Target), "-s", "base", "-b", "", "defaultNamingContext"}
	ldapSearchPath := fmt.Sprintf("%sldapsearch_base_discovery.out", dir)
	commands.CallRunTool(ldapSearchArgs, ldapSearchPath, checks.OptVVerbose)

	// LDAPSearch - Anonymous bind to enumerate everything (if allowed)
	ldapSearchFullArgs := []string{"ldapsearch", "-x", "-H", fmt.Sprintf("ldap://%s", utils.Target), "-b", ""}
	ldapSearchFullPath := fmt.Sprintf("%sldapsearch_anonymous_dump.out", dir)
	commands.CallRunTool(ldapSearchFullArgs, ldapSearchFullPath, checks.OptVVerbose)

	// Create helper file with manual enumeration instructions
	filePath := dir + "ldap_manual_enum_tips.txt"
	message := fmt.Sprintf(`LDAP Enumeration Tips:

1. Check the base discovery output to find the base DN:
   less -R %sldapsearch_base_discovery.out

2. Once you have the base DN (e.g., DC=example,DC=com), run:
   ldapsearch -x -H ldap://%s -b "DC=example,DC=com"

3. Try common LDAP queries:
   # List all users
   ldapsearch -x -H ldap://%s -b "DC=example,DC=com" "(objectClass=user)"

   # List all groups
   ldapsearch -x -H ldap://%s -b "DC=example,DC=com" "(objectClass=group)"

   # List all computers
   ldapsearch -x -H ldap://%s -b "DC=example,DC=com" "(objectClass=computer)"

4. If anonymous bind fails, try authenticated bind:
   ldapsearch -x -H ldap://%s -D "CN=username,DC=example,DC=com" -w password -b "DC=example,DC=com"

5. For LDAPS (port 636), use:
   ldapsearch -x -H ldaps://%s -b "DC=example,DC=com"
`, ldapSearchPath, utils.Target, utils.Target, utils.Target, utils.Target, utils.Target, utils.Target)
	if err := utils.WriteTextToFile(filePath, message); err != nil {
		utils.ErrorMsg(fmt.Sprintf("Failed to write LDAP enumeration tips file: %v", err))
	}
}

// Kerberos enumerates Kerberos Protocol (88/TCP)
func Kerberos() {
	dir := utils.ProtocolDetected("Kerberos", utils.BaseDir)
	nmapOutputFile := dir + "kerberos_scan"
	commands.CallIndividualPortScanner(utils.Target, "88", nmapOutputFile, checks.OptVVerbose)

	filePath := dir + "potential_DC_commands.txt"
	message := `
	Potential DC found. Enumerate further.
	Get the name of the domain and chuck it to:
	nmap -p 88 \ 
	--script=krb5-enum-users \
	--script-args krb5-enum-users.realm=\"{Domain_Name}\" \\n,userdb={Big_Userlist} \\n{IP}"`
	if err := utils.WriteTextToFile(filePath, message); err != nil {
		utils.ErrorMsg(fmt.Sprintf("Failed to write kerberos commands file: %v", err))
	}
}
