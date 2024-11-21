package config

import (
	"github.com/spf13/viper"
)

// subfeature weights for ip

type IPWeight struct {
	LoginIP float64 `mapstructure:"LoginIP"`
	ISP     float64 `mapstructure:"ISP"`
	Region  float64 `mapstructure:"Region"`
}

// subfeature weights for useragent
type UAWeight struct {
	BrowserNameandVersion         float64 `mapstructure:"Browser"`
	OperatingSystemNameandVersion float64 `mapstructure:"OS"`
}

type BFWeight struct {
	Fonts               float64 `mapstructure:"Fonts"`
	DeviceMemory        float64 `mapstructure:"DeviceMemory"`
	HardwareConcurrency float64 `mapstructure:"HardwareConcurrency"`
	Timezone            float64 `mapstructure:"Timezone"`
	CpuClass            float64 `mapstructure:"CpuClass"`
	Platform            float64 `mapstructure:"Platform"`
}

// weights of subfeatures for features
type Weights struct {
	IPWeight IPWeight `mapstructure:"ipweights"`
	UAWeight UAWeight `mapstructure:"uaweights"`
	BFWeight BFWeight `mapstructure:"bfweights"`
}

// FIXME: reconstruct the smoothing part
// exact unseen value for subfeatures
type SmoothingFactor struct {
	IPFactor                  float64 `mapstructure:"IPunseen"`
	ISPFactor                 float64 `mapstructure:"ISPunseen"`
	RegionFactor              float64 `mapstructure:"Regionunseen"`
	BrowserFactor             float64 `mapstructure:"Browserunseen"`
	OSFactor                  float64 `mapstructure:"OSunseen"`
	FontsFactor               float64 `mapstructure:"Fontsunseen"`
	DeviceMemoryFactor        float64 `mapstructure:"DeviceMemoryunseen"`
	HardwareConcurrencyFactor float64 `mapstructure:"HardwareConcurrencyunseen"`
	TimezoneFactor            float64 `mapstructure:"Timezoneunseen"`
	CpuClassFactor            float64 `mapstructure:"CpuClassunseen"`
	PlatformFactor            float64 `mapstructure:"Platformunseen"`
}

// feature weights
type FeatureWeights struct {
	IPWeight float64 `mapstructure:"ipweight"`
	UAWeight float64 `mapstructure:"uaweight"`
	BFWeight float64 `mapstructure:"bfweight"`
}

type Config struct {
	FeatureWeights   FeatureWeights  `mapstructure:"featureweights"`
	Weights          Weights         `mapstructure:"weights"`
	SmoothingFactors SmoothingFactor `mapstructure:"smoothingfactors"`
}

// Global configuration variable
var Configuration Config

// LoadConfig reads the configuration from the provided filename.
func LoadConfig(filename string) error {
	// Set the file name of the configurations file
	viper.SetConfigFile(filename)

	// Set the appropriate configuration file type
	viper.SetConfigType("json") // or "yaml", etc

	// Attempt to read the configuration file into viper's configuration registry
	if err := viper.ReadInConfig(); err != nil {
		return err
	}

	// Unmarshalling the configuration file contents into the Configuration variable
	if err := viper.Unmarshal(&Configuration); err != nil {
		return err
	}

	return nil
}
