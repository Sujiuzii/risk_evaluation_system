package config

import (
	"encoding/json"
	"fmt"
	"os"
)

type IPConfig struct {
	LoginIP float64 `json:"LoginIP"`
	ISP     float64 `json:"ISP"`
	City    float64 `json:"City"`
}

type UAConfig struct {
	BrowserNameandVersion         float64 `json:"BrowserNameandVersion"`
	OperatingSystemNameandVersion float64 `json:"OperatingSystemNameandVersion"`
	DeviceType                    float64 `json:"DeviceType"`
}

type Config struct {
	IP              IPConfig `json:"ip"`
	UA              UAConfig `json:"ua"`
	SmoothingFactor float64  `json:"smoothing_factor"`
	Threshold       float64  `json:"threshold"`
}

var Configuration Config

func LoadConfig(filename string) {
	file, err := os.Open(filename)
	if err != nil {
		fmt.Printf("Error opening config file: %v\n", err)
		return
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	err = decoder.Decode(&Configuration)
	if err != nil {
		fmt.Printf("Error parsing config file: %v\n", err)
	}
}
