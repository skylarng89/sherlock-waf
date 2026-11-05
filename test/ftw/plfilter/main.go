// Command plfilter prints a go-ftw --include regular expression that selects
// the CRS tests whose rule belongs to paranoia level <= N. Rules without a
// paranoia-level tag are PL1. Test ids look like "942100-3", so the output is
// "^(942100|942101|...)-".
package main

import (
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var (
	idRE = regexp.MustCompile(`\bid:\s*'?(\d+)`)
	plRE = regexp.MustCompile(`paranoia-level/(\d)`)
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: plfilter <crs rules dir> <max paranoia level>")
		os.Exit(2)
	}
	maxPL, err := strconv.Atoi(os.Args[2])
	if err != nil || maxPL < 1 || maxPL > 4 {
		fmt.Fprintln(os.Stderr, "plfilter: paranoia level must be 1-4")
		os.Exit(2)
	}
	if err := run(os.Args[1], maxPL); err != nil {
		fmt.Fprintln(os.Stderr, "plfilter:", err)
		os.Exit(1)
	}
}

func run(dir string, maxPL int) error {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()

	ids := map[string]bool{}
	err = fs.WalkDir(root.FS(), ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".conf") {
			return err
		}
		b, err := root.ReadFile(path)
		if err != nil {
			return err
		}
		// Join backslash continuations so each directive is one line.
		text := strings.ReplaceAll(string(b), "\\\n", " ")
		for _, line := range strings.Split(text, "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "SecRule") && !strings.HasPrefix(line, "SecAction") {
				continue
			}
			m := idRE.FindStringSubmatch(line)
			if m == nil {
				continue // chained rule part
			}
			pl := 1
			if p := plRE.FindStringSubmatch(line); p != nil {
				pl, _ = strconv.Atoi(p[1])
			}
			if pl <= maxPL {
				ids[m[1]] = true
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	list := make([]string, 0, len(ids))
	for id := range ids {
		list = append(list, id)
	}
	sort.Strings(list)
	fmt.Printf("^(%s)-\n", strings.Join(list, "|"))
	return nil
}
