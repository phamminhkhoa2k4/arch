// Command bench reports the correlation benchmark against a scan
// database and the ground truth file. Threshold misses print a
// GitHub Actions warning and exit 0; invalid inputs exit non-zero.
package main

import (
	"flag"
	"fmt"
	"os"

	"archaeologist/internal/bench"
)

func main() {
	db := flag.String("db", "lab/fixtures/scan.db", "path to the scan database")
	gt := flag.String("gt", "lab/ground-truth.yaml", "path to the ground truth yaml")
	flag.Parse()

	if err := bench.Run(*db, *gt, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "benchmark:", err)
		os.Exit(1)
	}
}
