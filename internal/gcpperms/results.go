package gcpperms

import (
	"encoding/json"
	"os"
	"slices"

	"github.com/cockroachdb/errors"
)

// LoadResults reads results saved with `analyze --format=json` from files
// and returns them as one result, binaries in file order.
func LoadResults(files []string) (Result, error) {
	const op = "gcpperms.LoadResults"
	var all Result
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			return Result{}, errors.Wrap(err, op)
		}
		var res Result
		if err := json.Unmarshal(data, &res); err != nil {
			return Result{}, errors.Wrapf(err, "%s: parsing %s", op, file)
		}
		all.Binaries = append(all.Binaries, res.Binaries...)
		all.Skipped = append(all.Skipped, res.Skipped...)
		all.Errors = append(all.Errors, res.Errors...)
	}
	return all, nil
}

// SelectBinaries returns the binaries of bins that packages name, in the
// order given, or every binary when packages is empty. It fails on a
// package bins has no binary for.
func SelectBinaries(bins []Binary, packages []string) ([]Binary, error) {
	if len(packages) == 0 {
		return bins, nil
	}
	out := make([]Binary, 0, len(packages))
	for _, pkg := range packages {
		i := slices.IndexFunc(bins, func(b Binary) bool { return b.Package == pkg })
		if i < 0 {
			return nil, errors.Errorf("no binary %s in the results", pkg)
		}
		out = append(out, bins[i])
	}
	return out, nil
}
