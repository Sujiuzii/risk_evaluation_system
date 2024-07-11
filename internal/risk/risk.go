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
	"math"
	"strconv"
	"sync"
	"time"

	"risk_evaluation_system/config"
	"risk_evaluation_system/internal/preprocessing"
)

// record the occurrence of each feature
type LogChecker struct {
	ipMap                  map[string]int
	ispMap                 map[string]int
	regionMap              map[string]int
	browserNameMap         map[string]int
	browserVersionMap      map[string]int
	osNameMap              map[string]int
	osVersionMap           map[string]int
	fontsMap               map[string]int
	deviceMemoryMap        map[string]int
	hardwareConcurrencyMap map[string]int
	timezoneMap            map[string]int
	cpuClassMap            map[string]int
	platformMap            map[string]int
	totalCount             int
	config                 config.Config
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

		mutexes["region"].Lock()
		maps["region"][log.Region]++
		mutexes["region"].Unlock()

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

		mutexes["fonts"].Lock()
		maps["fonts"][log.Fonts]++
		mutexes["fonts"].Unlock()

		mutexes["deviceMemory"].Lock()
		maps["deviceMemory"][strconv.Itoa(log.DeviceMemory)]++
		mutexes["deviceMemory"].Unlock()

		mutexes["hardwareConcurrency"].Lock()
		maps["hardwareConcurrency"][strconv.Itoa(log.HardwareConcurrency)]++
		mutexes["hardwareConcurrency"].Unlock()

		mutexes["timezone"].Lock()
		maps["timezone"][log.Timezone]++
		mutexes["timezone"].Unlock()

		mutexes["cpuClass"].Lock()
		maps["cpuClass"][log.CpuClass]++
		mutexes["cpuClass"].Unlock()

		mutexes["platform"].Lock()
		maps["platform"][log.Platform]++
		mutexes["platform"].Unlock()
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
	regionMap := make(map[string]int)
	browserNameMap := make(map[string]int)
	browserVersionMap := make(map[string]int)
	osNameMap := make(map[string]int)
	osVersionMap := make(map[string]int)
	fontsMap := make(map[string]int)
	deviceMemoryMap := make(map[string]int)
	hardwareConcurrencyMap := make(map[string]int)
	timezoneMap := make(map[string]int)
	cpuClassMap := make(map[string]int)
	platformMap := make(map[string]int)

	maps := map[string]map[string]int{
		"ip":                  ipMap,
		"isp":                 ispMap,
		"region":              regionMap,
		"browserName":         browserNameMap,
		"browserVersion":      browserVersionMap,
		"osName":              osNameMap,
		"osVersion":           osVersionMap,
		"fonts":               fontsMap,
		"deviceMemory":        deviceMemoryMap,
		"hardwareConcurrency": hardwareConcurrencyMap,
		"timezone":            timezoneMap,
		"cpuClass":            cpuClassMap,
		"platform":            platformMap,
	}

	var wg sync.WaitGroup
	n := len(logs)

	// TODO: consider better chunk numbers
	chunks := 4
	chunkSize := n / chunks

	// Initialize mutexes
	mutexes := map[string]*sync.Mutex{
		"ip":                  &sync.Mutex{},
		"isp":                 &sync.Mutex{},
		"region":              &sync.Mutex{},
		"browserName":         &sync.Mutex{},
		"browserVersion":      &sync.Mutex{},
		"osName":              &sync.Mutex{},
		"osVersion":           &sync.Mutex{},
		"fonts":               &sync.Mutex{},
		"deviceMemory":        &sync.Mutex{},
		"hardwareConcurrency": &sync.Mutex{},
		"timezone":            &sync.Mutex{},
		"cpuClass":            &sync.Mutex{},
		"platform":            &sync.Mutex{},
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
		ipMap:                  ipMap,
		ispMap:                 ispMap,
		regionMap:              regionMap,
		browserNameMap:         browserNameMap,
		browserVersionMap:      browserVersionMap,
		osNameMap:              osNameMap,
		osVersionMap:           osVersionMap,
		fontsMap:               fontsMap,
		deviceMemoryMap:        deviceMemoryMap,
		hardwareConcurrencyMap: hardwareConcurrencyMap,
		timezoneMap:            timezoneMap,
		cpuClassMap:            cpuClassMap,
		platformMap:            platformMap,
		totalCount:             n,
		config:                 configs,
	}
}

func (lc *LogChecker) getUnseenIp() float64 {
	knownCities := float64(len(lc.ipMap))
	knownISPs := float64(len(lc.ispMap))

	unseenCities := lc.config.SmoothingFactors.RegionFactor
	unseenISPs := lc.config.SmoothingFactors.ISPFactor
	unseenIPs := lc.config.SmoothingFactors.IPFactor

	return ((unseenCities+knownCities)*unseenISPs + knownISPs) * unseenIPs
}

func (lc *LogChecker) getUnseenIsp() float64 {
	knownCities := float64(len(lc.regionMap))

	unseenCities := lc.config.SmoothingFactors.RegionFactor
	unseenISPs := lc.config.SmoothingFactors.ISPFactor

	return (unseenCities + knownCities) * unseenISPs
}

func (lc *LogChecker) getUnseenCity() float64 {
	return lc.config.SmoothingFactors.RegionFactor
}

func (lc *LogChecker) getUnseenforIPSubfeature(subfeature string) (float64, error) {
	if subfeature == "ip" {
		return lc.getUnseenIp(), nil
	} else if subfeature == "isp" {
		return lc.getUnseenIsp(), nil
	} else if subfeature == "region" {
		return lc.getUnseenCity(), nil
	} else {
		return 0, fmt.Errorf("unknown subfeature: %s", subfeature)
	}

}

// TODO: different for ip and other features
// get the unseen value of a subfeature(fixed value for now)
func (lc *LogChecker) getUnseenCount(subfeature string) (float64, error) {
	switch subfeature {
	case "ip", "isp", "region":
		return lc.getUnseenforIPSubfeature(subfeature)
	case "browser":
		return lc.config.SmoothingFactors.BrowserFactor, nil
	case "os":
		return lc.config.SmoothingFactors.OSFactor, nil
	case "fonts":
		return lc.config.SmoothingFactors.FontsFactor, nil
	case "deviceMemory":
		return lc.config.SmoothingFactors.DeviceMemoryFactor, nil
	case "hardwareConcurrency":
		return lc.config.SmoothingFactors.HardwareConcurrencyFactor, nil
	case "timezone":
		return lc.config.SmoothingFactors.TimezoneFactor, nil
	case "cpuClass":
		return lc.config.SmoothingFactors.CpuClassFactor, nil
	case "platform":
		return lc.config.SmoothingFactors.PlatformFactor, nil
	default:
		return 0, fmt.Errorf("unknown feature: %s", subfeature)
	}
}

// get the occurrence rate of a subfeature for a user
func (lc *LogChecker) GetOccurrenceRateUserSub(attempt preprocessing.LogAttemptVector, subfeature string) (float64, error) {
	// M, err := lc.getUnseenCount(subfeature)
	// if err != nil {
	// 	return 0, err
	// }

	a := 1.0 / (float64(lc.totalCount) * 1.05)
	var count int

	switch subfeature {
	case "ip":
		count = lc.ipMap[attempt.LoginIP]
	case "isp":
		count = lc.ispMap[attempt.ISP]
	case "region":
		count = lc.regionMap[attempt.Region]
	case "browser":
		count = lc.browserNameMap[attempt.BrowserName]
	case "os":
		count = lc.osNameMap[attempt.OSName]
	case "fonts":
		count = lc.fontsMap[attempt.Fonts]
	case "deviceMemory":
		count = lc.deviceMemoryMap[strconv.Itoa(attempt.DeviceMemory)]
	case "hardwareConcurrency":
		count = lc.hardwareConcurrencyMap[strconv.Itoa(attempt.HardwareConcurrency)]
	case "timezone":
		count = lc.timezoneMap[attempt.Timezone]
	case "cpuClass":
		count = lc.cpuClassMap[attempt.CpuClass]
	case "platform":
		count = lc.platformMap[attempt.Platform]
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
		case "region":
			return weights.Region, nil
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
		default:
			return 0, fmt.Errorf("unknown feature: %s", subfeature)
		}
	} else if feature == "bf" {
		weights := config.Configuration.Weights.BFWeight

		switch subfeature {
		case "fonts":
			return weights.Fonts, nil
		case "deviceMemory":
			return weights.DeviceMemory, nil
		case "hardwareConcurrency":
			return weights.HardwareConcurrency, nil
		case "timezone":
			return weights.Timezone, nil
		case "cpuClass":
			return weights.CpuClass, nil
		case "platform":
			return weights.Platform, nil
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
	start := time.Now()
	defer func() {
		duration := time.Since(start)
		fmt.Printf("Risk scoring time: %s\n", duration)
	}()
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
		w   float64
		err error
	}

	// rateCh := make(chan rateResult, len(features))
	rateCh := make(chan rateResult, len(config.Features))
	var wg sync.WaitGroup
	start2 := time.Now()
	defer func() {
		duration := time.Since(start2)
		fmt.Printf("Function execution time: %s\n", duration)
	}()

	for feature := range config.Features {
		wg.Add(1)
		go func(feature string) {
			defer wg.Done()

			pxu, err := userLogChecker.GetOccurrenceRateUser(attempt, feature)
			w := 0.0
			if feature == "ip" {
				w = config.Configuration.FeatureWeights.IPWeight
			} else if feature == "ua" {
				w = config.Configuration.FeatureWeights.UAWeight
			} else {
				w = config.Configuration.FeatureWeights.BFWeight
			}
			fmt.Println(feature, " pxu: ", pxu)
			if err != nil {
				rateCh <- rateResult{0, 0, 0, err}
				return
			}

			// px, err := userLogChecker.GetOccurrenceRateGlobal(attempt, feature, logs)
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
	close(rateCh)

	for r := range rateCh {
		if r.err != nil {
			return 0, r.err
		}
		result *= math.Pow(r.px/r.pxu, r.w)
	}

	return result, nil
}
