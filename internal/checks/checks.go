package checks

import (
	"fmt"
	"github.com/0x5ubt13/enumeraga/internal/cloud"
	"github.com/0x5ubt13/enumeraga/internal/infra"
	"github.com/0x5ubt13/enumeraga/internal/utils"
	"os"
)

// Run pre-flight checks and return total lines if multi-target
func Run() int {
	// Set current version
	utils.Version = "v0.2.0-beta"

	// Check if infra flow or cloud flow apply
	if len(os.Args) < 2 {
		utils.ErrorMsg("You need to choose between `enumeraga infra` or `enumeraga cloud`")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "c", "cl", "clo", "clou", "cloud":
		fmt.Printf("\n%s%s%s\n", utils.Cyan("[*] ---------- "), utils.Green("Starting Cloud checks phase"), utils.Cyan(" ----------"))

		cloud.Run()
	case "i", "in", "inf", "infr", "infra":
		// Infra checks now moved to internal/infra/infra.go
		totalLines := infra.Run()

		if !*infra.OptQuiet {
			fmt.Printf("\n%s%s%s\n", utils.Cyan("[*] ---------- "), utils.Green("Starting Infra checks phase"), utils.Cyan(" ----------"))
		}
		return totalLines

	default:
		utils.ErrorMsg("You need to choose between `enumeraga infra` or `enumeraga cloud`")
		os.Exit(1)
	}

	return 0
}
