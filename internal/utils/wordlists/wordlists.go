package wordlists

import (
	"fmt"

	"github.com/0x5ubt13/enumeraga/internal/utils/output"
	"github.com/mattn/go-zglob"
)

// Global wordlist path variables
var (
	// DarkwebTop1000 and others below are globally available wordlists
	DarkwebTop1000 string
	ExtensionsList string
	UsersList      string
	SnmpList       string
	DirListMedium  string

	// wordlistsLocated ensures GetWordlists only runs once
	wordlistsLocated bool
)

// GetWordlists locates and caches SecLists wordlist paths
func GetWordlists(optVVerbose *bool) error {
	if wordlistsLocated {
		return nil
	}
	wordlistsLocated = true

	var missingWordlists []string

	// Locate the "raft-medium-directories-lowercase" file
	dirListMediumSlice, err := zglob.Glob("/usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt")
	if err != nil || len(dirListMediumSlice) == 0 {
		missingWordlists = append(missingWordlists, "raft-medium-directories-lowercase.txt")
		output.PrintCustomBiColourMsg("red", "cyan", "[-] Warning: ", "Could not locate 'raft-medium-directories-lowercase.txt' - directory bruteforcing may not work")
	} else {
		DirListMedium = dirListMediumSlice[0]
	}

	// Locate the "darkweb2017-top1000.txt" file
	DarkwebTop1000Slice, err := zglob.Glob("/usr/share/seclists/Passwords/darkweb2017-top1000.txt")
	if err != nil || len(DarkwebTop1000Slice) == 0 {
		missingWordlists = append(missingWordlists, "darkweb2017-top1000.txt")
		output.PrintCustomBiColourMsg("red", "cyan", "[-] Warning: ", "Could not locate 'darkweb2017-top1000.txt' - password bruteforcing may not work")
	} else {
		DarkwebTop1000 = DarkwebTop1000Slice[0]
	}

	// Locate the "web-extensions.txt" file
	ExtensionsListSlice, err := zglob.Glob("/usr/share/seclists/Discovery/Web-Content/web-extensions.txt")
	if err != nil || len(ExtensionsListSlice) == 0 {
		missingWordlists = append(missingWordlists, "web-extensions.txt")
		output.PrintCustomBiColourMsg("red", "cyan", "[-] Warning: ", "Could not locate 'web-extensions.txt' - extension fuzzing may not work")
	} else {
		ExtensionsList = ExtensionsListSlice[0]
	}

	// Locate the "top-usernames-shortlist" file
	UsersListSlice, err := zglob.Glob("/usr/share/seclists/Usernames/top-usernames-shortlist.txt")
	if err != nil || len(UsersListSlice) == 0 {
		missingWordlists = append(missingWordlists, "top-usernames-shortlist.txt")
		output.PrintCustomBiColourMsg("red", "cyan", "[-] Warning: ", "Could not locate 'top-usernames-shortlist.txt' - user enumeration may not work")
	} else {
		UsersList = UsersListSlice[0]
	}

	// Locate the "snmp-onesixtyone" file
	snmpListSlice, err := zglob.Glob("/usr/share/seclists/Discovery/SNMP/snmp-onesixtyone.txt")
	if err != nil || len(snmpListSlice) == 0 {
		missingWordlists = append(missingWordlists, "snmp-onesixtyone.txt")
		output.PrintCustomBiColourMsg("red", "cyan", "[-] Warning: ", "Could not locate 'snmp-onesixtyone.txt' - SNMP enumeration may not work")
	} else {
		SnmpList = snmpListSlice[0]
	}

	if *optVVerbose {
		fmt.Println("Located Files:")
		fmt.Printf("dir_list_medium: %v\n", DirListMedium)
		fmt.Printf("darkweb_top1000: %v\n", DarkwebTop1000)
		fmt.Printf("extensions_list: %v\n", ExtensionsList)
		fmt.Printf("users_list: %v\n", UsersList)
		fmt.Printf("snmp_list: %v\n", SnmpList)
	}

	// Return error only if ALL wordlists are missing
	if len(missingWordlists) == 5 {
		return fmt.Errorf("no wordlists found - please install seclists or ensure wordlists are in /usr/share/seclists/")
	}

	return nil
}
