package config

// var Features = [][]string{
// 	{"LoginIP", "ISP", "City"},
// 	{"BrowserName", "BrowserVersion"},
// 	{"OSName", "OSVersion"},
// 	{"DeviceType"},
// }

var Features = map[string][]string{
	"ip": {"ip", "isp", "city"},
	"ua": {"browser", "os", "device"},
}
