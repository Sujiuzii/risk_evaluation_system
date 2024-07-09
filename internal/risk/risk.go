// Description: Package risk is the core of the risk evaluation system.
// It provides the Freeman risk scoring algorithm to evaluate the risk of a user.
//
// The LogChecker struct records the occurrence of each feature in the logs.
// The Freeman function calculates the risk score of a user based on the log data.
//
// ! This version is weak in accuracy
package risk

import (
	"fmt"
	"sync"
	"time"

	"risk_evaluation_system/config"
	"risk_evaluation_system/internal/preprocessing"
)

// record the occurrence of each feature
type LogChecker struct {
	ipMap             map[string]int
	ispMap            map[string]int
	cityMap           map[string]int
	browserNameMap    map[string]int
	browserVersionMap map[string]int
	osNameMap         map[string]int
	osVersionMap      map[string]int
	deviceTypeMap     map[string]int
	totalCount        int
	config            config.Config
}

// use goroutines and mutexes to count the occurrence of each feature
func processLogs(logs []preprocessing.LogFeatureEntry, wg *sync.WaitGroup, maps map[string]map[string]int, mutexes map[string]*sync.Mutex) {
	defer wg.Done()

	for _, log := range logs {
		mutexes["ip"].Lock()
		maps["ip"][log.LoginIP]++
		mutexes["ip"].Unlock()

		mutexes["isp"].Lock()
		maps["isp"][log.ISP]++
		mutexes["isp"].Unlock()

		mutexes["city"].Lock()
		maps["city"][log.City]++
		mutexes["city"].Unlock()

		mutexes["browserName"].Lock()
		maps["browserName"][log.BrowserName]++
		mutexes["browserName"].Unlock()

		mutexes["browserVersion"].Lock()
		maps["browserVersion"][log.BrowserVersion]++
		mutexes["browserVersion"].Unlock()

		mutexes["osName"].Lock()
		maps["osName"][log.OSName]++
		mutexes["osName"].Unlock()

		mutexes["osVersion"].Lock()
		maps["osVersion"][log.OSVersion]++
		mutexes["osVersion"].Unlock()

		mutexes["deviceType"].Lock()
		maps["deviceType"][log.DeviceType]++
		mutexes["deviceType"].Unlock()
	}
}

// constructor for LogChecker(expensive)
func NewLogChecker(logs []preprocessing.LogFeatureEntry, configs config.Config) *LogChecker {
	start := time.Now()
	defer func() {
		duration := time.Since(start)
		fmt.Printf("LogChecker setup time: %s\n", duration)
	}()
	ipMap := make(map[string]int)
	ispMap := make(map[string]int)
	cityMap := make(map[string]int)
	browserNameMap := make(map[string]int)
	browserVersionMap := make(map[string]int)
	osNameMap := make(map[string]int)
	osVersionMap := make(map[string]int)
	deviceTypeMap := make(map[string]int)

	maps := map[string]map[string]int{
		"ip":             ipMap,
		"isp":            ispMap,
		"city":           cityMap,
		"browserName":    browserNameMap,
		"browserVersion": browserVersionMap,
		"osName":         osNameMap,
		"osVersion":      osVersionMap,
		"deviceType":     deviceTypeMap,
	}

	var wg sync.WaitGroup
	n := len(logs)

	// TODO: consider better chunk numbers
	chunks := 4
	chunkSize := n / chunks

	// Initialize mutexes
	mutexes := map[string]*sync.Mutex{
		"ip":             &sync.Mutex{},
		"isp":            &sync.Mutex{},
		"city":           &sync.Mutex{},
		"browserName":    &sync.Mutex{},
		"browserVersion": &sync.Mutex{},
		"osName":         &sync.Mutex{},
		"osVersion":      &sync.Mutex{},
		"deviceType":     &sync.Mutex{},
	}

	for i := 0; i < chunks; i++ {
		start := i * chunkSize
		end := start + chunkSize
		if i == chunks-1 {
			end = n
		}
		wg.Add(1)
		go processLogs(logs[start:end], &wg, maps, mutexes)
	}

	wg.Wait()

	return &LogChecker{
		ipMap:             ipMap,
		ispMap:            ispMap,
		cityMap:           cityMap,
		browserNameMap:    browserNameMap,
		browserVersionMap: browserVersionMap,
		osNameMap:         osNameMap,
		osVersionMap:      osVersionMap,
		deviceTypeMap:     deviceTypeMap,
		totalCount:        n,
		config:            configs,
	}
}

// ? May need a dynamic version unseen value
// TODO: need a recursive version
// ? may need different version for different features
// get the unseen value of a subfeature(fixed value for now)
func (lc *LogChecker) GetUnseenCount(attempt preprocessing.LogAttemptVector, subfeature string, configs config.Config) (float64, error) {
	switch subfeature {
	case "ip":
		return configs.SmoothingFactors.IPFactor, nil
	case "isp":
		return configs.SmoothingFactors.ISPFactor, nil
	case "city":
		return configs.SmoothingFactors.CityFactor, nil
	case "browser":
		return configs.SmoothingFactors.BrowserFactor, nil
	case "os":
		return configs.SmoothingFactors.OSFactor, nil
	case "device":
		return configs.SmoothingFactors.DeviceTypeFactor, nil
	default:
		return 0, fmt.Errorf("unknown feature: %s", subfeature)
	}
}

// get the occurrence rate of a subfeature for a user
func (lc *LogChecker) GetOccurrenceRateUserSub(attempt preprocessing.LogAttemptVector, subfeature string) (float64, error) {
	M, err := lc.GetUnseenCount(attempt, subfeature, lc.config)
	if err != nil {
		return 0, err
	}

	a := 1.0 / (float64(lc.totalCount) + M)
	var count int

	switch subfeature {
	case "ip":
		count = lc.ipMap[attempt.LoginIP]
	case "isp":
		count = lc.ispMap[attempt.ISP]
	case "city":
		count = lc.cityMap[attempt.City]
	case "browser":
		count = lc.browserNameMap[attempt.BrowserName]
	case "os":
		count = lc.osNameMap[attempt.OSName]
	case "device":
		count = lc.deviceTypeMap[attempt.DeviceType]
	default:
		return 0, fmt.Errorf("unknown feature: %s", subfeature)
	}

	if count == 0 {
		return a, nil
	}

	return float64(count) * a, nil
}

// ? expensive for frequent calls
// FIXME: consider to store the weights
// parse weight from config for exact subfeature
func checkWeight(subfeature string, feature string) (float64, error) {
	if feature == "ip" {
		weights := config.Configuration.Weights.IPWeight

		switch subfeature {
		case "ip":
			return weights.LoginIP, nil
		case "isp":
			return weights.ISP, nil
		case "city":
			return weights.City, nil
		default:
			return 0, fmt.Errorf("unknown feature: %s", subfeature)
		}
	} else if feature == "ua" {
		weights := config.Configuration.Weights.UAWeight

		switch subfeature {
		case "browser":
			return weights.BrowserNameandVersion, nil
		case "os":
			return weights.OperatingSystemNameandVersion, nil
		case "device":
			return weights.DeviceType, nil
		default:
			return 0, fmt.Errorf("unknown feature: %s", subfeature)
		}
	} else {
		return 0, fmt.Errorf("unknown feature: %s", feature)
	}
}

// ! bad implementation
// FIXME: merge with GetOccurrenceRateUserSub
// get the occurrence rate of a subfeature globally
func (lc *LogChecker) GetOccurrenceRateGlobalSub(attempt preprocessing.LogAttemptVector, subfeature string, logs []preprocessing.LogFeatureEntry) (float64, error) {
	logChecker := NewLogChecker(logs, lc.config)

	return logChecker.GetOccurrenceRateUserSub(attempt, subfeature)
}

// check occurrence rate for subfeatures and weight them into a single value
func (lc *LogChecker) GetOccurrenceRateUser(attempt preprocessing.LogAttemptVector, feature string) (float64, error) {
	subfeatures, ok := config.Features[feature]
	if !ok {
		return 0, fmt.Errorf("unknown feature: %s", feature)
	}

	var result float64
	result = 0
	for _, subfeature := range subfeatures {
		if weight, err := checkWeight(subfeature, feature); err != nil {
			return 0, err
		} else {
			pxu, err := lc.GetOccurrenceRateUserSub(attempt, subfeature)
			if err != nil {
				return 0, err
			}
			result += weight * pxu
		}
	}

	return result, nil
}

// ! bad implementation
// FIXME: merge with GetOccurrenceRateUser
// get the occurrence rate of a feature globally
func (lc *LogChecker) GetOccurrenceRateGlobal(attempt preprocessing.LogAttemptVector, feature string, logs []preprocessing.LogFeatureEntry) (float64, error) {
	subfeatures, ok := config.Features[feature]
	if !ok {
		return 0, fmt.Errorf("unknown feature: %s", feature)
	}

	var result float64
	result = 0
	for _, subfeature := range subfeatures {
		if weight, err := checkWeight(subfeature, feature); err != nil {
			return 0, err
		} else {
			px, err := lc.GetOccurrenceRateGlobalSub(attempt, subfeature, logs)
			if err != nil {
				return 0, err
			}
			result += weight * px
		}
	}

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

// ! poor implementation
// TODO: weight every feature differently
// TODO: consider involving the ip reputation system and something in
// TODO: better the performance by merging the log checkers
// TODO: more features needed
// Freeman risk scoring algorithm
func Freeman(attempt preprocessing.LogAttemptVector, logs []preprocessing.LogFeatureEntry) (float64, error) {
	// start := time.Now()
	// defer func() {
	// 	duration := time.Since(start)
	// 	fmt.Printf("Risk scoring time: %s\n", duration)
	// }()
	userID := attempt.UserID

	userLogs := filterLogsByUserID(userID, logs)

	userLogChecker := NewLogChecker(userLogs, config.Configuration)
	globalLogChecker := NewLogChecker(logs, config.Configuration)

	// features := []string{"ip", "isp", "city", "browser", "os", "device"}

	puL, err := userLogChecker.GetUserOccurrenceRate(logs)

	if err != nil {
		return 0, err
	}

	// ! no login history, need double check
	// BUG: bad for first time login
	if puL == 0 {
		return 0, fmt.Errorf("empty log checker")
	}
	result := 1.0 / puL

	type rateResult struct {
		px  float64
		pxu float64
		err error
	}

	// rateCh := make(chan rateResult, len(features))
	rateCh := make(chan rateResult, len(config.Features))
	var wg sync.WaitGroup
	// start2 := time.Now()
	// defer func() {
	// 	duration := time.Since(start2)
	// 	fmt.Printf("Function execution time: %s\n", duration)
	// }()

	for feature := range config.Features {
		wg.Add(1)
		go func(feature string) {
			defer wg.Done()

			pxu, err := userLogChecker.GetOccurrenceRateUser(attempt, feature)
			if err != nil {
				rateCh <- rateResult{0, 0, err}
				return
			}

			// px, err := userLogChecker.GetOccurrenceRateGlobal(attempt, feature, logs)
			px, err := globalLogChecker.GetOccurrenceRateUser(attempt, feature)
			println(feature, " px: ", px)
			if err != nil {
				rateCh <- rateResult{0, 0, err}
				return
			}

			rateCh <- rateResult{px, pxu, nil}
		}(feature)
	}

	wg.Wait()
	close(rateCh)

	for r := range rateCh {
		if r.err != nil {
			return 0, r.err
		}
		result *= r.px / r.pxu
	}

	return result, nil
}
