// Command bench reports the correlation benchmark plus the Checkpoint
// #2 false-orphan/precision metrics, recall, and integrity numbers
// against a scan database and the ground truth file. Correlation
// threshold misses print a GitHub Actions warning and exit 0; a
// checkpoint miss exits 1 so the CI job blocks the merge. Invalid
// inputs exit non-zero.
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
	rulesFile := flag.String("rules", "lab/rules.lab.yaml", "path to the rules file for verdict computation")
	observeLog := flag.String("observe-log", "",
		"optional observe-sla sampler log for the overhead metric")
	history := flag.String("out", "",
		"append one JSON line of run metrics to this history file")
	flag.Parse()

	if err := bench.Run(*db, *gt, *rulesFile, *observeLog, *history, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "benchmark:", err)
		os.Exit(1)
	}
}
