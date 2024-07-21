// Description: This file contains the features that can be used to
package config

var Features = map[string][]string{
	"ip": {"ip", "isp", "region"},
	"ua": {"browser", "os"},
	"bf": {
		"fonts",
		"deviceMemory",
		"hardwareConcurrency",
		"timezone",
		"cpuClass",
		"platform",
	},
}
