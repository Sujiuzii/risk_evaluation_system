package config

import (
	"encoding/json"
	"os"
)

type IPWeight struct {
	LoginIP float64 `json:"LoginIP"`
	ISP     float64 `json:"ISP"`
	City    float64 `json:"City"`
}

type UAWeight struct {
	BrowserNameandVersion         float64 `json:"Browser"`
	OperatingSystemNameandVersion float64 `json:"OS"`
	DeviceType                    float64 `json:"Device"`
}

type Weights struct {
	IPWeight IPWeight `json:"ipweights"`
	UAWeight UAWeight `json:"uaweights"`
}

type SmoothingFactor struct {
	IPFactor         float64 `json:"IPunseen"`
	ISPFactor        float64 `json:"ISPunseen"`
	CityFactor       float64 `json:"Cityunseen"`
	BrowserFactor    float64 `json:"Browserunseen"`
	OSFactor         float64 `json:"OSunseen"`
	DeviceTypeFactor float64 `json:"Deviceunseen"`
}

type FeatureWeights struct {
	IPWeight float64 `json:"ipweight"`
	UAWeight float64 `json:"uaweight"`
}

type Config struct {
	FeatureWeights   FeatureWeights  `json:"featureweights"`
	Weights          Weights         `json:"weights"`
	SmoothingFactors SmoothingFactor `json:"smoothingfactors"`
}

var Configuration Config

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
