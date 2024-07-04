package utils

import (
	"regexp"
	"strings"

	"github.com/mssola/useragent"
)

func CleanString(input string) string {
	return strings.TrimSpace(input)
}

func DetermineDeviceType(userAgent string) string {
	ua := useragent.New(userAgent)
	if ua.Mobile() {
		return "Mobile"
	} else if ua.Bot() {
		return "Bot"
	} else if ua.Platform() == "Windows" || ua.Platform() == "Linux" || ua.Platform() == "Macintosh" {
		return "Desktop/Laptop"
	} else {
		return "Unknown"
	}
}

func ExtractBrowserFingerprinting(userAgent string) string {
	pattern := `(?i)Mozilla\/.*\(([^)]+)\)`
	re := regexp.MustCompile(pattern)
	matches := re.FindStringSubmatch(userAgent)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}
