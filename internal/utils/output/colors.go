package output

import (
	"fmt"

	"github.com/fatih/color"
)

// Color function variables for terminal output
var (
	// Yellow prints a message in yellow colour
	Yellow = color.New(color.FgYellow).SprintFunc()

	// Red prints a message in red colour
	Red = color.New(color.FgRed).SprintFunc()

	// Green prints a message in green colour
	Green = color.New(color.FgHiGreen).SprintFunc()

	// Cyan prints a message in cyan colour
	Cyan = color.New(color.FgCyan).SprintFunc()

	// Debug prints a message in magenta colour
	Debug = color.New(color.FgMagenta).SprintFunc()
)

// Printer provides color printing functionality
type Printer struct {
	colors map[string]func(...interface{}) string
}

// NewPrinter creates a new printer with color registry
func NewPrinter() *Printer {
	return &Printer{
		colors: map[string]func(...interface{}) string{
			"green":   Green,
			"yellow":  Yellow,
			"red":     Red,
			"cyan":    Cyan,
			"magenta": Debug,
		},
	}
}

// getColor retrieves a color function from the registry
func (p *Printer) getColor(name string) func(...interface{}) string {
	if colorFunc, exists := p.colors[name]; exists {
		return colorFunc
	}
	// Default to no color if not found
	return func(a ...interface{}) string {
		return fmt.Sprint(a...)
	}
}

// PrintCustomBiColourMsg loops over the necessary colours, printing one at a time
// This is the optimized version using a color registry instead of nested switches
func PrintCustomBiColourMsg(dominantColour, secondaryColour string, text ...string) {
	printer := NewPrinter()

	for i, str := range text {
		var colorFunc func(...interface{}) string
		if i%2 == 0 || i == 0 {
			colorFunc = printer.getColor(dominantColour)
		} else {
			colorFunc = printer.getColor(secondaryColour)
		}
		fmt.Printf("%s", colorFunc(str))
	}
	fmt.Printf("\n")
}

// PrintBanner displays the enumeraga ASCII art banner with version information.
func PrintBanner(version string) {
	fmt.Printf("\n%s\n", Cyan("                                                     ", version))
	fmt.Printf("%s%s%s\n", Yellow(" __________                                    ________"), Cyan("________"), Yellow("______ "))
	fmt.Printf("%s%s%s\n", Yellow(" ___  ____/__________  ________ __________________    |"), Cyan("_  ____/"), Yellow("__    |"))
	fmt.Printf("%s%s%s\n", Yellow(" __  __/  __  __ \\  / / /_  __ `__ \\  _ \\_  ___/_  /| |"), Cyan("  / __ "), Yellow("__  /| |"))
	fmt.Printf("%s%s%s\n", Yellow(" _  /___  _  / / / /_/ /_  / / / / /  __/  /   _  ___ "), Cyan("/ /_/ / "), Yellow("_  ___ |"))
	fmt.Printf("%s%s%s\n", Yellow(" /_____/  /_/ /_/\\__,_/ /_/ /_/ /_/\\___//_/    /_/  |_"), Cyan("\\____/  "), Yellow("/_/  |_|"))
	fmt.Printf("%s\n\n", Green("                            by 0x5ubt13"))
}

// PrintInfraUsageExamples displays example command line usage for infrastructure scanning mode.
func PrintInfraUsageExamples() {
	e := color.WhiteString("enumeraga ")

	// Print "examples" in white
	fmt.Printf("\nExamples:\n ")
	PrintCustomBiColourMsg(
		"cyan", "yellow",
		e, "-i\n ",
		e, "-bq -t ", "10.10.11.230", "\n ",
		e, "-V -r ", "10.129.121.0/24", " -t ", "10.129.121.60", "\n ",
		e, "-t ", "targets_file.txt", " -r ", "10.10.8.0/24",
	)
}

// PrintCloudUsageExamples displays example command line usage for cloud scanning mode.
func PrintCloudUsageExamples() {
	e := color.WhiteString("enumeraga cloud ")

	// Print "examples" in white
	fmt.Printf("\nExamples:\n ")
	PrintCustomBiColourMsg(
		"cyan", "yellow",
		e, "aws\n ",
		e, "gcp\n ",
		e, "azure",
	)
}
