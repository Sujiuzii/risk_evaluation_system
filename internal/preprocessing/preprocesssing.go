package preprocessing

import (
	"encoding/csv"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"risk_evaluation_system/internal/utils"

	"github.com/mssola/useragent"
)

// LogEntry represents a single log entry.
type LogEntry struct {
	UserID                string
	GID                   string
	LogTime               time.Time
	ObjectiveSystem       string
	LoginIP               string
	BrowserFingerprinting string
	Country               string
	RegionName            string
	City                  string
	ISP                   string
	Org                   string
	AS                    string
	Agent                 string
	BrowserName           string
	BrowserVersion        string
	OSName                string
	OSVersion             string
	DeviceType            string
}

// LogFeatureEntry represents a single log entry with extracted partial features.
type LogFeatureEntry struct {
	UserID         string
	LogTime        time.Time
	LoginIP        string
	City           string
	ISP            string
	BrowserName    string
	BrowserVersion string
	OSName         string
	OSVersion      string
	DeviceType     string
}

// LoginAttempt represents a single login attempt.
type LoginAttempt LogEntry
type LogAttemptVector LogFeatureEntry

func parseLogEntry(record []string) (LogEntry, error) {
	logTime, err := time.Parse("2006-01-02 15:04", record[2])
	if err != nil {
		return LogEntry{}, fmt.Errorf("failed to parse log time: %v", err)
	}

	ua := useragent.New(record[12])
	browserName, browserVersion := ua.Browser()
	osName, osVersion := ua.OSInfo().Name, ua.OSInfo().Version
	deviceType := getDeviceType(record[12])

	return LogEntry{
		UserID:                utils.CleanString(record[0]),
		GID:                   utils.CleanString(record[1]),
		LogTime:               logTime,
		ObjectiveSystem:       utils.CleanString(record[3]),
		LoginIP:               utils.CleanString(record[4]),
		BrowserFingerprinting: utils.CleanString(record[5]),
		Country:               utils.CleanString(record[6]),
		RegionName:            utils.CleanString(record[7]),
		City:                  utils.CleanString(record[8]),
		ISP:                   utils.CleanString(record[9]),
		Org:                   utils.CleanString(record[10]),
		AS:                    utils.CleanString(record[11]),
		Agent:                 utils.CleanString(record[12]),
		BrowserName:           browserName,
		BrowserVersion:        browserVersion,
		OSName:                osName,
		OSVersion:             osVersion,
		DeviceType:            deviceType,
	}, nil
}

func getDeviceType(uA string) string {
	ua := useragent.New(uA)
	if ua.Mobile() {
		return "Mobile"
	} else if ua.Bot() {
		return "Bot"
	} else if ua.Platform() == "Windows" || ua.Platform() == "Linux" || ua.Platform() == "Macintosh" {
		return "Desktop/Laptop"
	} else {
		return "Unknown"
	}
}

func extractFeatures(logs []LogEntry) []LogFeatureEntry {
	wg := sync.WaitGroup{}
	wg.Add(len(logs))

	logFeatureEntries := make([]LogFeatureEntry, len(logs))
	for i, log := range logs {
		go func(i int, log LogEntry) {
			defer wg.Done()

			logFeatureEntries[i] = LogFeatureEntry{
				UserID:         log.UserID,
				LogTime:        log.LogTime,
				LoginIP:        log.LoginIP,
				City:           log.City,
				ISP:            log.ISP,
				BrowserName:    log.BrowserName,
				BrowserVersion: log.BrowserVersion,
				OSName:         log.OSName,
				OSVersion:      log.OSVersion,
				DeviceType:     log.DeviceType,
			}
		}(i, log)
	}

	wg.Wait()
	return logFeatureEntries
}

func processChunk(lines [][]string, wg *sync.WaitGroup, results chan<- LogEntry, errors chan<- error) {
	defer wg.Done()
	for _, line := range lines {
		if entry, err := parseLogEntry(line); err == nil {
			results <- entry
		} else {
			errors <- err
		}
	}
}

func PreprocessLogs(filePath string) ([]LogEntry, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %v", err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	reader.FieldsPerRecord = -1 // Allow variable fields

	if record, err := reader.Read(); err != nil {
		return nil, fmt.Errorf("failed to read header: %v", err)
	} else {
		fmt.Println("Header:", record)
	}

	results := make(chan LogEntry)
	errors := make(chan error)
	var wg sync.WaitGroup

	chunkSize := 1000
	var chunk [][]string

	alllogs, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("failed to read all logs: %v", err)
	}

	for _, line := range alllogs {
		chunk = append(chunk, line)

		if len(chunk) >= chunkSize {
			wg.Add(1)
			go processChunk(chunk, &wg, results, errors)
			chunk = nil // Reset chunk
		}
	}

	if len(chunk) > 0 {
		wg.Add(1)
		go processChunk(chunk, &wg, results, errors)
	}

	go func() {
		wg.Wait()
		close(results)
		close(errors)
	}()

	var logs []LogEntry
	for entry := range results {
		logs = append(logs, entry)
	}

	if err, ok := <-errors; ok {
		return nil, fmt.Errorf("error processing logs: %v", err)
	}

	return logs, nil
}

func LoadNewLoginAttempt(filePath string) (LoginAttempt, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return LoginAttempt{}, err
	}
	defer file.Close()

	reader := csv.NewReader(file)
	reader.FieldsPerRecord = -1

	records, err := reader.ReadAll()
	if err != nil {
		return LoginAttempt{}, err
	}

	if len(records) < 2 {
		return LoginAttempt{}, fmt.Errorf("no valid records in new attempt file")
	}

	attempt := records[1] // Assume first row is header, second row is the actual data
	logTime, err := time.Parse("2006-01-02 15:04", attempt[2])
	if err != nil {
		return LoginAttempt{}, err
	}

	ua := useragent.New(attempt[12])
	browserName, browserVersion := ua.Browser()
	osName := ua.OSInfo().Name
	osVersion := ua.OSInfo().Version
	deviceType := getDeviceType(attempt[12])

	return LoginAttempt{
		UserID:                utils.CleanString(attempt[0]),
		GID:                   utils.CleanString(attempt[1]),
		LogTime:               logTime,
		ObjectiveSystem:       utils.CleanString(attempt[3]),
		LoginIP:               utils.CleanString(attempt[4]),
		BrowserFingerprinting: utils.CleanString(attempt[5]),
		Country:               utils.CleanString(attempt[6]),
		RegionName:            utils.CleanString(attempt[7]),
		City:                  utils.CleanString(attempt[8]),
		ISP:                   utils.CleanString(attempt[9]),
		Org:                   utils.CleanString(attempt[10]),
		AS:                    utils.CleanString(attempt[11]),
		Agent:                 utils.CleanString(attempt[12]),
		BrowserName:           browserName,
		BrowserVersion:        browserVersion,
		OSName:                osName,
		OSVersion:             osVersion,
		DeviceType:            deviceType,
	}, nil
}

func PrepareLogFeatures(logs []LogEntry) []LogFeatureEntry {
	return extractFeatures(logs)
}

func GetLoginAttemptVector(attempt LoginAttempt) LogAttemptVector {
	return LogAttemptVector{
		UserID:         attempt.UserID,
		LogTime:        attempt.LogTime,
		LoginIP:        attempt.LoginIP,
		City:           attempt.City,
		ISP:            attempt.ISP,
		BrowserName:    attempt.BrowserName,
		BrowserVersion: attempt.BrowserVersion,
		OSName:         attempt.OSName,
		OSVersion:      attempt.OSVersion,
		DeviceType:     attempt.DeviceType,
	}
}

func String2LogAttemptVector(log string) LogAttemptVector {
	fields := strings.Split(log, ",")

	logTime, _ := time.Parse("2006-01-02 15:04", fields[1])

	ua := useragent.New(fields[12])
	browserName, browserVersion := ua.Browser()
	osName := ua.OSInfo().Name
	osVersion := ua.OSInfo().Version
	deviceType := getDeviceType(fields[12])

	return LogAttemptVector{
		UserID:         fields[0],
		LogTime:        logTime,
		LoginIP:        fields[4],
		City:           fields[8],
		ISP:            fields[9],
		BrowserName:    browserName,
		BrowserVersion: browserVersion,
		OSName:         osName,
		OSVersion:      osVersion,
		DeviceType:     deviceType,
	}
}
