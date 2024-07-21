// Description: Package config contains the configuration parser for the risk evaluation system.
//
// The LoadConfig function reads the configuration file and loads the configuration into the global Configuration variable.
// Load with config.LoadConfig("config.json") and use the config.Configuration
package config

import (
	// TODO: consider using viper for configuration management
	"encoding/json"
	"os"
)

// subfeature weights for ip
type IPWeight struct {
	LoginIP float64 `json:"LoginIP"`
	ISP     float64 `json:"ISP"`
	Region  float64 `json:"Region"`
}

// subfeature weights for useragent
type UAWeight struct {
	BrowserNameandVersion         float64 `json:"Browser"`
	OperatingSystemNameandVersion float64 `json:"OS"`
}

type BFWeight struct {
	Fonts               float64 `json:"Fonts"`
	DeviceMemory        float64 `json:"DeviceMemory"`
	HardwareConcurrency float64 `json:"HardwareConcurrency"`
	Timezone            float64 `json:"Timezone"`
	CpuClass            float64 `json:"CpuClass"`
	Platform            float64 `json:"Platform"`
}

// weights of subfeatures for features
type Weights struct {
	IPWeight IPWeight `json:"ipweights"`
	UAWeight UAWeight `json:"uaweights"`
	BFWeight BFWeight `json:"bfweights"`
}

// ! bad implementation
// FIXME: reconstruct the smoothing part
// exact unseen value for subfeatures
type SmoothingFactor struct {
	IPFactor                  float64 `json:"IPunseen"`
	ISPFactor                 float64 `json:"ISPunseen"`
	RegionFactor              float64 `json:"Regionunseen"`
	BrowserFactor             float64 `json:"Browserunseen"`
	OSFactor                  float64 `json:"OSunseen"`
	FontsFactor               float64 `json:"Fontsunseen"`
	DeviceMemoryFactor        float64 `json:"DeviceMemoryunseen"`
	HardwareConcurrencyFactor float64 `json:"HardwareConcurrencyunseen"`
	TimezoneFactor            float64 `json:"Timezoneunseen"`
	CpuClassFactor            float64 `json:"CpuClassunseen"`
	PlatformFactor            float64 `json:"Platformunseen"`
}

// feature weights
type FeatureWeights struct {
	IPWeight float64 `json:"ipweight"`
	UAWeight float64 `json:"uaweight"`
	BFWeight float64 `json:"bfweight"`
}

// configuration struct
type Config struct {
	FeatureWeights   FeatureWeights  `json:"featureweights"`
	Weights          Weights         `json:"weights"`
	SmoothingFactors SmoothingFactor `json:"smoothingfactors"`
}

// global configuration variable
var Configuration Config

// parse the config file and load the configuration into the global Configuration variable
func LoadConfig(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	err = decoder.Decode(&Configuration)
	if err != nil {
		return err
	}

	return nil
}
