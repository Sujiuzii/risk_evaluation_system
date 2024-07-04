package tests

import (
	"risk_evaluation_system/internal/preprocessing"
	"risk_evaluation_system/internal/risk"
	"testing"
	"time"
)

func TestEvaluateRisk(t *testing.T) {
	featureWeights := map[string]float64{
		"IPScore":     0.3,
		"UAScore":     0.3,
		"DeviceScore": 0.4,
	}
	riskEvaluator := risk.NewRiskEvaluator(featureWeights)

	logs := []preprocessing.LogEntry{
		{UserID: "user1", LogTime: time.Now()},
		{UserID: "user1", LogTime: time.Now().Add(-time.Hour)},
	}

	attempt := preprocessing.LoginAttempt{
		UserID:  "user1",
		LogTime: time.Now(),
	}

	result := riskEvaluator.EvaluateRisk(attempt, logs, logs)

	if result.UserID != "user1" {
		t.Errorf("Expected UserID to be 'user1', got %s", result.UserID)
	}

	if result.LoginAttemptNumber != 3 {
		t.Errorf("Expected LoginAttemptNumber to be 3, got %d", result.LoginAttemptNumber)
	}
}

func TestEvaluateAllRisks(t *testing.T) {
	featureWeights := map[string]float64{
		"IPScore":     0.3,
		"UAScore":     0.3,
		"DeviceScore": 0.4,
	}
	riskEvaluator := risk.NewRiskEvaluator(featureWeights)

	logs := []preprocessing.LogEntry{
		{UserID: "user1", LogTime: time.Now()},
		{UserID: "user1", LogTime: time.Now().Add(-time.Hour)},
		{UserID: "user2", LogTime: time.Now()},
	}

	attempts := []preprocessing.LoginAttempt{
		{UserID: "user1", LogTime: time.Now()},
		{UserID: "user2", LogTime: time.Now()},
	}

	results := riskEvaluator.EvaluateAllRisks(attempts, logs)

	if len(results) != 2 {
		t.Errorf("Expected 2 results, got %d", len(results))
	}

	for _, result := range results {
		if result.UserID == "" {
			t.Error("Expected non-empty UserID")
		}
	}
}
