// Description: Package config contains the configuration parser for the risk evaluation system.
//
// The LoadConfig function reads the configuration file and loads the configuration into the global Configuration variable.
// Load with config.LoadConfig("config.json") and use the config.Configuration
package config

import (
	// ? consider using viper for configuration management
	"encoding/json"
	"os"
)

// subfeature weights for ip
type IPWeight struct {
	LoginIP float64 `json:"LoginIP"`
	ISP     float64 `json:"ISP"`
	City    float64 `json:"City"`
}

// subfeature weights for useragent
type UAWeight struct {
	BrowserNameandVersion         float64 `json:"Browser"`
	OperatingSystemNameandVersion float64 `json:"OS"`
	DeviceType                    float64 `json:"Device"`
}

// weights of subfeatures for features
type Weights struct {
	IPWeight IPWeight `json:"ipweights"`
	UAWeight UAWeight `json:"uaweights"`
}

// ! bad implementation
// FIXME: reconstruct the smoothing part
// exact unseen value for subfeatures
type SmoothingFactor struct {
	IPFactor         float64 `json:"IPunseen"`
	ISPFactor        float64 `json:"ISPunseen"`
	CityFactor       float64 `json:"Cityunseen"`
	BrowserFactor    float64 `json:"Browserunseen"`
	OSFactor         float64 `json:"OSunseen"`
	DeviceTypeFactor float64 `json:"Deviceunseen"`
}

// TODO: not using this yet
// feature weights
type FeatureWeights struct {
	IPWeight float64 `json:"ipweight"`
	UAWeight float64 `json:"uaweight"`
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
