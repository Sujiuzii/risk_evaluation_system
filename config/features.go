// Description: This file contains the features to be used
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
