package preprocessing

import (
	// "bufio"
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"risk_evaluation_system/internal/utils"
	"sync"
	"time"

	"github.com/mssola/useragent"
)

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

type LoginAttempt struct {
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

func parseLogEntry(record []string) (LogEntry, error) {
	logTime, err := time.Parse("2006-01-02 15:04", record[2])
	if err != nil {
		return LogEntry{}, err
	}

	ua := useragent.New(record[12])
	browserName, browserVersion := ua.Browser()
	osName := ua.OSInfo().Name
	osVersion := ua.OSInfo().Version
	deviceType := utils.DetermineDeviceType(record[12])

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
		return nil, err
	}
	defer file.Close()

	// fmt.Println("Reading file...", filePath)

	reader := csv.NewReader(file)
	reader.FieldsPerRecord = -1 // Allow variable fields

	// Read header
	if record, err := reader.Read(); err != nil {
		return nil, err
	} else {
		fmt.Println("Header:", record)
	}

	// Setup channels and wait group
	results := make(chan LogEntry)
	errors := make(chan error)
	var wg sync.WaitGroup

	// scanner := bufio.NewScanner(file)
	chunkSize := 1000
	var chunk [][]string

	// ? Will the ReadAll() function read the entire file into memory? Is it a good idea? Expensive?
	alllogs, err := reader.ReadAll()
	if err != nil {
		log.Fatalf("Error reading logs: %v", err)
	}

	for _, line := range alllogs {
		chunk = append(chunk, line)

		if len(chunk) >= chunkSize {
			wg.Add(1)
			go processChunk(chunk, &wg, results, errors)
			chunk = nil // Reset chunk
		}
	}

	// Process the last chunk
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
	for {
		select {
		case entry, ok := <-results:
			if !ok {
				results = nil
			} else {
				logs = append(logs, entry)
			}
		case err, ok := <-errors:
			if !ok {
				errors = nil
			} else {
				return nil, err
			}
		}
		if results == nil && errors == nil {
			break
		}
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
	deviceType := utils.DetermineDeviceType(attempt[12])

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
