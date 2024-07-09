// PASS
package tests

import (
	"risk_evaluation_system/internal/preprocessing"
	"testing"
)

func TestPreprocessLogs(t *testing.T) {
	// // logs, err := preprocessing.PreprocessLogs("../data/example_log.csv")
	logs, err := preprocessing.PreprocessLogs("/home/suhui/Projects/risk_engine/dataset/merged_log-20240210.csv")
	if err != nil {
		t.Fatalf("Failed to preprocess logs: %v", err)
	}
	if len(logs) == 0 {
		t.Error("Expected some log entries, got none")
	}
}

func TestLoadNewLoginAttempt(t *testing.T) {
	attempt, err := preprocessing.LoadNewLoginAttempt("../data/new_attempt.csv")
	if err != nil {
		t.Fatalf("Failed to load new login attempt: %v", err)
	}
	if attempt.UserID == "" {
		t.Error("Expected a valid UserID, got an empty string")
	}
}
