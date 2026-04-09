package main

import (
	"os"

	"github.com/codeswhat/sockguard/internal/cmd"
)

var execute = cmd.Execute
var exitProcess = os.Exit

func main() {
	if err := execute(); err != nil {
		exitProcess(1)
	}
}
