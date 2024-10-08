// Description: Package risk is the core of the risk evaluation system.
// It provides the Freeman risk scoring algorithm to evaluate the risk of a user.
//
// The LogChecker struct records the occurrence of each feature in the logs.
// The Freeman function calculates the risk score of a user based on the log data.
package risk

import (
	"fmt"
	"math"
	"sync"
	"time"

	"risk_evaluation_system/config"
	"risk_evaluation_system/internal/preprocessing"
)

// TODO: make daily log checker as a new struct, and hierarchically set the log checkers
// 此处 config.Config 为全局变量，不应该在这里使用，考虑将其作为参数传入
// record the occurrence of each feature
type LogChecker struct {
	ipMap          map[string]int
	ispMap         map[string]int
	regionMap      map[string]int
	browserNameMap map[string]int
	osNameMap      map[string]int
	platformMap    map[string]int
	totalCount     int
}

// use goroutines and mutexes to count the occurrence of each feature
// 辅助函数，用于处理日志
func processLogs(logs []preprocessing.LogFeatureEntry, wg *sync.WaitGroup, maps map[string]map[string]int, mutexes map[string]*sync.Mutex) {
	defer wg.Done()

	for _, log := range logs {
		mutexes["ip"].Lock()
		maps["ip"][log.LoginIP]++
		mutexes["ip"].Unlock()

		mutexes["isp"].Lock()
		maps["isp"][log.ISP]++
		mutexes["isp"].Unlock()

		mutexes["region"].Lock()
		maps["region"][log.Region]++
		mutexes["region"].Unlock()

		mutexes["browserName"].Lock()
		maps["browserName"][log.BrowserName]++
		mutexes["browserName"].Unlock()

		mutexes["osName"].Lock()
		maps["osName"][log.OSName]++
		mutexes["osName"].Unlock()

		mutexes["platform"].Lock()
		maps["platform"][log.Platform]++
		mutexes["platform"].Unlock()
	}
}

// constructor for LogChecker(expensive)
// 构造器，在本实现中将建立针对用户以及全局的日志检查器
func NewLogChecker(logs []preprocessing.LogFeatureEntry, configs config.Config) *LogChecker {
	start := time.Now()
	defer func() {
		duration := time.Since(start)
		fmt.Printf("LogChecker setup time: %s\n", duration)
	}()
	ipMap := make(map[string]int)
	ispMap := make(map[string]int)
	regionMap := make(map[string]int)
	browserNameMap := make(map[string]int)
	osNameMap := make(map[string]int)
	platformMap := make(map[string]int)

	maps := map[string]map[string]int{
		"ip":          ipMap,
		"isp":         ispMap,
		"region":      regionMap,
		"browserName": browserNameMap,
		"osName":      osNameMap,
		"platform":    platformMap,
	}

	var wg sync.WaitGroup
	n := len(logs)

	numWorkers := 4
	chunkSize := n / numWorkers

	mutexes := map[string]*sync.Mutex{
		"ip":          &sync.Mutex{},
		"isp":         &sync.Mutex{},
		"region":      &sync.Mutex{},
		"browserName": &sync.Mutex{},
		"osName":      &sync.Mutex{},
		"platform":    &sync.Mutex{},
	}

	for i := 0; i < numWorkers; i++ {
		start := i * chunkSize
		end := start + chunkSize
		if i == numWorkers-1 {
			end = n
		}
		wg.Add(1)
		go processLogs(logs[start:end], &wg, maps, mutexes)
	}

	wg.Wait()

	return &LogChecker{
		ipMap:          ipMap,
		ispMap:         ispMap,
		regionMap:      regionMap,
		browserNameMap: browserNameMap,
		osNameMap:      osNameMap,
		platformMap:    platformMap,
		totalCount:     n,
	}
}

func (lc *LogChecker) GetOccurrenceRateUserSub(attempt preprocessing.LogAttemptVector, subfeature string) (float64, error) {
	a := 1.0 / (float64(lc.totalCount) + 1.0)
	var count int

	switch subfeature {
	case "isp":
		count = lc.ispMap[attempt.ISP]
	case "region":
		count = lc.regionMap[attempt.Region]
	case "browser":
		count = lc.browserNameMap[attempt.BrowserName]
	case "os":
		count = lc.osNameMap[attempt.OSName]
	case "fingerprint":
		count = lc.platformMap[attempt.Platform]
	default:
		return 0, fmt.Errorf("unknown feature: %s", subfeature)
	}

	if count == 0 {
		return a, nil
	}

	return float64(count) * a, nil
}

// check occurrence rate for subfeatures and weight them into a single value
func (lc *LogChecker) GetOccurrenceRateUser(attempt preprocessing.LogAttemptVector, feature string) (float64, error) {
	result := 0.0
	// TODO

	return result, nil
}

// check the userID occurrence rate in all logs
func (lc *LogChecker) GetUserOccurrenceRate(logs []preprocessing.LogFeatureEntry) (float64, error) {
	if len(logs) == 0 {
		return 0, fmt.Errorf("empty log checker")
	}
	return float64(lc.totalCount) / float64(len(logs)), nil
}

// filter logs by userID
func filterLogsByUserID(userID string, logs []preprocessing.LogFeatureEntry) []preprocessing.LogFeatureEntry {
	var wg sync.WaitGroup

	// TODO: consider better chunk numbers
	numWorkers := 4
	chunkSize := (len(logs) + numWorkers - 1) / numWorkers

	resultCh := make(chan []preprocessing.LogFeatureEntry, numWorkers)

	for i := 0; i < numWorkers; i++ {
		start := i * chunkSize
		end := start + chunkSize
		if end > len(logs) {
			end = len(logs)
		}

		wg.Add(1)
		go func(logChunk []preprocessing.LogFeatureEntry) {
			defer wg.Done()
			userLogs := make([]preprocessing.LogFeatureEntry, 0)
			for _, log := range logChunk {
				if log.UserID == userID {
					userLogs = append(userLogs, log)
				}
			}
			resultCh <- userLogs
		}(logs[start:end])
	}

	wg.Wait()
	close(resultCh)

	userLogs := make([]preprocessing.LogFeatureEntry, 0)
	for logs := range resultCh {
		userLogs = append(userLogs, logs...)
	}

	return userLogs
}

func Freeman(attempt preprocessing.LogAttemptVector, logs []preprocessing.LogFeatureEntry) (float64, error) {
	start := time.Now()
	defer func() {
		duration := time.Since(start)
		fmt.Printf("Risk scoring time: %s\n", duration)
	}()
	userID := attempt.UserID

	userLogs := filterLogsByUserID(userID, logs)

	userLogChecker := NewLogChecker(userLogs, config.Configuration)
	globalLogChecker := NewLogChecker(logs, config.Configuration)

	puL, err := userLogChecker.GetUserOccurrenceRate(logs)

	if err != nil {
		return 0, err
	}

	if puL == 0 {
		return 1e10, nil
	}
	result := 1.0 / puL

	type rateResult struct {
		px  float64
		pxu float64
		w   float64
		err error
	}

	rateCh := make(chan rateResult, len(config.Features))
	var wg sync.WaitGroup

	for _, feature := range config.Features {
		wg.Add(1)
		go func(feature string) {
			defer wg.Done()

			var w float64
			if feature == "isp" {
				w = config.Configuration.FeatureWeights.ISPWeight
			} else if feature == "region" {
				w = config.Configuration.FeatureWeights.RegionWeight
			} else if feature == "browser" {
				w = config.Configuration.FeatureWeights.BrowserWeight
			} else if feature == "os" {
				w = config.Configuration.FeatureWeights.OSWeight
			} else {
				w = config.Configuration.FeatureWeights.FingerprintWeight
			}

			pxu, err := userLogChecker.GetOccurrenceRateUser(attempt, feature)
			fmt.Println(feature, " pxu: ", pxu)
			if err != nil {
				rateCh <- rateResult{0, 0, 0, err}
				return
			}

			px, err := globalLogChecker.GetOccurrenceRateUser(attempt, feature)
			fmt.Println(feature, " px: ", px)
			if err != nil {
				rateCh <- rateResult{0, 0, 0, err}
				return
			}

			rateCh <- rateResult{px, pxu, w, nil}
		}(feature)
	}

	wg.Wait()

	// 在所有值都计算完毕后，关闭通道
	close(rateCh)

	for r := range rateCh {
		if r.err != nil {
			return 0, r.err
		}
		result *= math.Pow(r.px/r.pxu, r.w)
	}

	return result, nil
}
