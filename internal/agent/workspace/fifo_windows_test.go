//go:build windows

package workspace

import "errors"

var errNoFifo = errors.New("fifos unsupported on windows")

// makeFifo is unavailable on Windows: the FIFO test skips gracefully.
func makeFifo(path string) error {
	return errNoFifo
}
