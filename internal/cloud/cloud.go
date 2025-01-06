package cloud

import (
	"fmt"
	"github.com/0x5ubt13/enumeraga/internal/cloudScanner"
	"github.com/0x5ubt13/enumeraga/internal/utils"
	"os"
)

var (
// include all cloud getopts here
)

func Run() {

	// Check 3.5: if this is for cloud, get into cloud flow instead
	cloudArg := os.Args[1]

	switch cloudArg {
	case "c", "cl", "clo", "clou", "cloud":
		fmt.Println(utils.Cyan("[*] Cloud argument detected. Starting Cloud enumeration.\n"))
		cloudScanner.Run()
		/* placeholder for when 'enumeraga infra' and enumeraga 'cloud' are both implemented
		case "i", "in", "inf", "infr", "infra":
		*/
	}
}
