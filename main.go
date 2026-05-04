package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/palmerc/androidzip/zip"
)

func main() {
	jsonOut := flag.Bool("json", false, "output report as JSON")
	quiet := flag.Bool("quiet", false, "suppress output; rely on exit code only (exit 2 = issues found)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: androidzip [flags] <file.apk>\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(1)
	}
	path := flag.Arg(0)

	f, err := os.Open(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	archive, err := zip.OpenReader(f)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse: %v\n", err)
		os.Exit(1)
	}

	report := zip.BuildReport(path, archive)

	if !*quiet {
		if *jsonOut {
			if err := zip.WriteJSON(os.Stdout, report); err != nil {
				fmt.Fprintf(os.Stderr, "json: %v\n", err)
				os.Exit(1)
			}
		} else {
			zip.WriteText(os.Stdout, report)
		}
	}

	if report.IssueCount > 0 {
		os.Exit(2) // non-zero exit lets CI/scripts detect malformed APKs
	}
}
