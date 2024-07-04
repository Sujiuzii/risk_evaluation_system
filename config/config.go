package config

import (
    "encoding/json"
    "os"
)

type Config struct {
    IPWeight       float64 `json:"ip_weight"`
    UAWeight       float64 `json:"ua_weight"`
    OSWeight       float64 `json:"os_weight"`
    DeviceWeight   float64 `json:"device_weight"`
    BrowserWeight  float64 `json:"browser_weight"`
    OtherWeights map[string]float64 `json:"other_weights"`
}

func LoadConfig(filePath string) (*Config, error) {
    file, err := os.Open(filePath)
    if err != nil {
        return nil, err
    }
    defer file.Close()

    var config Config
    decoder := json.NewDecoder(file)
    if err := decoder.Decode(&config); err != nil {
        return nil, err
    }

    return &config, nil
}

