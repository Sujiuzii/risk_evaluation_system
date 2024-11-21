package tests

import (
	"fmt"
	"testing"

	"risk_evaluation_system/config"

	"github.com/stretchr/testify/assert"
)

func TestLoadConfig(t *testing.T) {
	err := config.LoadConfig("config.json")
	fmt.Println(config.Configuration)
	assert.Nil(t, err)
	assert.Equal(t, 0.2, config.Configuration.FeatureWeights.IPWeight)
	assert.Equal(t, 0.05, config.Configuration.Weights.IPWeight.LoginIP)
}
