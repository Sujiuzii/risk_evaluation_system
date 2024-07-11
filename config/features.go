// Description: This file contains the features that can be used to
package config

// TODO: Add more features, and reconstruct the features to use
// TODO: Browser fingerprint
// 可信设备列表
// features to use
// var Features = map[string][]string{
// 	"ip": {"ip", "isp", "city"},
// 	"ua": {"browser", "os", "device"},
// }

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
