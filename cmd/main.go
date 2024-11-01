package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"log"
	"os"
	"risk_evaluation_system/config"
	"risk_evaluation_system/internal/preprocessing"
	"risk_evaluation_system/internal/risk"
)

func main() {

	logFilePath := flag.String("log-file", "../../data/combined_logs.csv", "Path to the log file")
	newAttemptFilePath := flag.String("attempt-file", "../../data/need_test.csv", "Path to the new login attempt file")
	outputFilePath := flag.String("output-file", "../../data/output_test.csv", "Path to the output result file")
	priodLogNum := flag.Int("log-num", 1, "The number of priod logs for DUBA")
	methodName := flag.String("method-name", "DUBA", "Risk Score method name")
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

	attemptFile, err := os.Open(*newAttemptFilePath)
	if err != nil {
		log.Fatalf("Error opening new login attempt file: %v", err)
	}
	defer attemptFile.Close()

	// 打开或创建输出文件
	file, err := os.OpenFile(*outputFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Error opening or creating file: %v", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	info, err := file.Stat()
	if err != nil {
		log.Fatalf("Error getting file info: %v", err)
	}
	if info.Size() == 0 {
		if err := writer.Write([]string{"UserID", "Score"}); err != nil {
			log.Fatalf("Error writing header to CSV: %v", err)
		}
	}
	reader := csv.NewReader(attemptFile)
	records, err := reader.ReadAll()
	if err != nil {
		log.Fatalf("Error reading login attempt file: %v", err)
	}

	// 假设第一行是表头，将其与后续的尝试记录分开
	header := records[0]
	attemptRecords := records[1:]

	// 遍历每一条登录尝试
	for i, record := range attemptRecords {
		// 创建临时文件，写入表头和当前登录尝试的内容
		tmpFile, err := os.CreateTemp("../", "attempt_*.csv")
		if err != nil {
			log.Fatalf("Error creating temporary file: %v", err)
		}
		defer os.Remove(tmpFile.Name())

		writerTmp := csv.NewWriter(tmpFile)

		// 写入表头
		if err := writerTmp.Write(header); err != nil {
			log.Fatalf("Error writing header to temporary file: %v", err)
		}

		// 写入当前的登录尝试记录
		if err := writerTmp.Write(record); err != nil {
			log.Fatalf("Error writing record to temporary file: %v", err)
		}
		writerTmp.Flush()
		tmpFile.Close()

		// 读取并处理当前的登录尝试
		attempt, err := preprocessing.LoadNewLoginAttempt(tmpFile.Name())
		if err != nil {
			log.Fatalf("Error loading new login attempt: %v", err)
		}
		fmt.Printf("Processing login attempt %d: %+v\n", i+1, attempt)

		attemptvec := preprocessing.GetLoginAttemptVector(attempt)
		logsf := preprocessing.PrepareLogFeatures(logs)

		//计算风险分数
		if *methodName == "DUBA" {
			if score, userID, err := risk.GetRiskScore(attemptvec, logsf); err != nil {
				log.Fatalf("Error evaluating risk score: %v", err)
			} else {
				// 写入输出文件
				if i%*priodLogNum == 0 {
					if err := writer.Write([]string{userID, fmt.Sprintf("%f", score)}); err != nil {
						log.Fatalf("Error writing data to output CSV: %v", err)
					}
					fmt.Printf("Written UserID: %s, Score: %f to output CSV\n", userID, score)
				}
			}
		} else {

			if risk, userID, err := risk.Freeman(attemptvec, logsf); err != nil {
				log.Fatalf("Error evaluating risk: %v", err)
			} else {
				if err := writer.Write([]string{userID, fmt.Sprintf("%f", risk)}); err != nil {
					log.Fatalf("Error writing data to output CSV: %v", err)
				}
				if risk > 10000 {
					risk = 10000
				}
				fmt.Printf("Written UserID: %s, Score: %f to output CSV\n", userID, risk)
			}
		}
	}
}
