// Description: Package main connects the preprocessing and risk packages to the risk evaluation system.
//
// pass the parameters in the command line
// // this package can be used to analyze time consumption of the system
package main

import (
	"flag"
	"fmt"
	"log"
	"risk_evaluation_system/config"
	"risk_evaluation_system/internal/preprocessing"
	"risk_evaluation_system/internal/risk"
)

func main() {
	// 增加了两个参数，用于指定日志文件和新的登录尝试文件
	logFilePath := flag.String("log-file", "data/example_log.csv", "Path to the log file")
	newAttemptFilePath := flag.String("attempt-file", "data/new_attempt.csv", "Path to the new login attempt file")
	flag.Parse()

	if err := config.LoadConfig("config/config.json"); err != nil {
		log.Fatalf("Error loading configuration: %v", err)
	}

	// 日志预处理
	logs, err := preprocessing.PreprocessLogs(*logFilePath)
	if err != nil {
		log.Fatalf("Error preprocessing logs: %v", err)
	}
	fmt.Printf("Processed %d log entries.\n", len(logs))

	// 加载新的登录尝试向量
	attempt, err := preprocessing.LoadNewLoginAttempt(*newAttemptFilePath)
	if err != nil {
		log.Fatalf("Error loading new login attempt: %v", err)
	}
	fmt.Printf("New login attempt: %+v\n", attempt)

	attemptvec := preprocessing.GetLoginAttemptVector(attempt)
	logsf := preprocessing.PrepareLogFeatures(logs)

	// 计算风险
	if risk, err := risk.Freeman(attemptvec, logsf); err != nil {
		log.Fatalf("Error evaluating risk: %v", err)
	} else {
		fmt.Printf("Risk: %f\n", risk)
	}
}
