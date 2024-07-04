package main

import (
	"flag"
	"fmt"
	"log"
	"risk_evaluation_system/internal/preprocessing"
)

func main() {
	logFilePath := flag.String("log-file", "data/example_log.csv", "Path to the log file")
	newAttemptFilePath := flag.String("attempt-file", "data/new_attempt.csv", "Path to the new login attempt file")
	flag.Parse()

	// Preprocess the logs
	logs, err := preprocessing.PreprocessLogs(*logFilePath)
	if err != nil {
		log.Fatalf("Error preprocessing logs: %v", err)
	}
	fmt.Printf("Processed %d log entries.\n", len(logs))

	// Load the new login attempt
	attempt, err := preprocessing.LoadNewLoginAttempt(*newAttemptFilePath)
	if err != nil {
		log.Fatalf("Error loading new login attempt: %v", err)
	}
	fmt.Printf("New login attempt: %+v\n", attempt)
}
