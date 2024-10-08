// Description: Package config contains the configuration parser for the risk evaluation system.
//
// The LoadConfig function reads the configuration file and loads the configuration into the global Configuration variable.
// Load with config.LoadConfig("config.json") and use the config.Configuration
package config

import (
	"encoding/json"
	"os"
)

// feature weights
type FeatureWeights struct {
	ISPWeight         float64 `json:"ispweight"`
	RegionWeight      float64 `json:"regionweight"`
	BrowserWeight     float64 `json:"browserweight"`
	OSWeight          float64 `json:"osweight"`
	FingerprintWeight float64 `json:"fingerprintweight"`
}

// configuration struct
type Config struct {
	FeatureWeights FeatureWeights `json:"featureweights"`
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
