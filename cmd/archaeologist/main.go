package main

import (
	"os"

	"archaeologist/internal/cli"
)

func main() {
	os.Exit(cli.Execute())
}
