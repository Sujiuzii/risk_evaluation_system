// Description: Package utils contains utility functions for the risk evaluation system.
package utils

import (
	"strings"
)

// remove leading and trailing whitespaces from a string
func CleanString(input string) string {
	return strings.TrimSpace(input)
}
