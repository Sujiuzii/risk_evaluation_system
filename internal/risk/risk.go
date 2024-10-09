// Description: Package risk is the core of the risk evaluation system.
// It provides the Freeman risk scoring algorithm to evaluate the risk of a user.
//
// The LogChecker struct records the occurrence of each feature in the logs.
// The Freeman function calculates the risk score of a user based on the log data.
package risk

import (
	"crypto/sha256"
	"fmt"
	"math"
	"sync"
	"time"

	"risk_evaluation_system/config"
	"risk_evaluation_system/internal/preprocessing"
)

// 简易的哈希函数，用于处理浏览器指纹空值的特殊情况
func hashString(s string) string {
	h := sha256.New()
	h.Write([]byte(s))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// record the occurrence of each feature
type LogChecker struct {
	ispMap         map[string]int
	regionMap      map[string]int
	browserNameMap map[string]int
	osNameMap      map[string]int
	fingerprintMap map[string]int
	totalCount     int
}

// use goroutines and mutexes to count the occurrence of each feature
// 辅助函数，用于处理日志
func processLogs(logs []preprocessing.LogFeatureEntry, wg *sync.WaitGroup, maps map[string]map[string]int, mutexes map[string]*sync.Mutex) {
	defer wg.Done()

	for _, log := range logs {
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

		mutexes["fingerprint"].Lock()
		maps["fingerprint"][log.Fingerprint]++
		mutexes["fingerprint"].Unlock()
	}
}

// constructor for LogChecker(expensive)
// 构造器，在本实现中将建立针对用户以及全局的日志检查器
func NewLogChecker(logs []preprocessing.LogFeatureEntry) *LogChecker {
	start := time.Now()
	defer func() {
		duration := time.Since(start)
		fmt.Printf("LogChecker setup time: %s\n", duration)
	}()
	ispMap := make(map[string]int)
	regionMap := make(map[string]int)
	browserNameMap := make(map[string]int)
	osNameMap := make(map[string]int)
	fingerprintMap := make(map[string]int)

	maps := map[string]map[string]int{
		"isp":         ispMap,
		"region":      regionMap,
		"browserName": browserNameMap,
		"osName":      osNameMap,
		"fingerprint": fingerprintMap,
	}

	var wg sync.WaitGroup
	n := len(logs)

	numWorkers := 4
	chunkSize := n / numWorkers

	mutexes := map[string]*sync.Mutex{
		"isp":         &sync.Mutex{},
		"region":      &sync.Mutex{},
		"browserName": &sync.Mutex{},
		"osName":      &sync.Mutex{},
		"fingerprint": &sync.Mutex{},
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
		ispMap:         ispMap,
		regionMap:      regionMap,
		browserNameMap: browserNameMap,
		osNameMap:      osNameMap,
		fingerprintMap: fingerprintMap,
		totalCount:     n,
	}
}

func (lc *LogChecker) GetOccurrenceRateUser(attempt preprocessing.LogAttemptVector, feature string) (float64, error) {
	a := 1.0 / (float64(lc.totalCount) + 1.0)
	var count int

	switch feature {
	case "isp":
		count = lc.ispMap[attempt.ISP]
	case "region":
		count = lc.regionMap[attempt.Region]
	case "browser":
		count = lc.browserNameMap[attempt.BrowserName]
		if attempt.BrowserName == "Unknown" || attempt.BrowserName == "" {
			count = 1
		}
	case "os":
		count = lc.osNameMap[attempt.OSName]
		if attempt.OSName == "Unknown" || attempt.OSName == "" {
			count = 1
		}
	case "fingerprint":
		count = lc.fingerprintMap[attempt.Fingerprint]
		if attempt.Fingerprint == hashString("Unknown") || attempt.Fingerprint == "" {
			count = 1
		}
	default:
		return 0, fmt.Errorf("unknown feature: %s", feature)
	}

	if count == 0 {
		return a, nil
	}
	return float64(count) * a, nil
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

func getWeight(configuration config.Config, feature string) float64 {
	var w float64
	switch feature {
	case "isp":
		w = configuration.FeatureWeights.ISPWeight
	case "region":
		w = configuration.FeatureWeights.RegionWeight
	case "browser":
		w = configuration.FeatureWeights.BrowserWeight
	case "os":
		w = configuration.FeatureWeights.OSWeight
	default:
		w = configuration.FeatureWeights.FingerprintWeight
	}
	return w
}

func Freeman(attempt preprocessing.LogAttemptVector, logs []preprocessing.LogFeatureEntry) (float64, error) {
	start := time.Now()
	defer func() {
		duration := time.Since(start)
		fmt.Printf("Risk scoring time: %s\n", duration)
	}()
	userID := attempt.UserID

	userLogs := filterLogsByUserID(userID, logs)

	userLogChecker := NewLogChecker(userLogs)
	globalLogChecker := NewLogChecker(logs)

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

			w := getWeight(config.Configuration, feature)

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

var Weights = map[string]float64{
	"isp":         0.2,
	"region":      0.2,
	"browserName": 0.2,
	"osName":      0.2,
	"fingerprint": 0.2,
}

func GetRiskScore(attempt preprocessing.LogAttemptVector, logs []preprocessing.LogFeatureEntry) (float64, error) {
	type probability struct {
		px  float64
		pxu float64
	}

	userID := attempt.UserID
	userLogs := filterLogsByUserID(userID, logs)

	userLogChecker := NewLogChecker(userLogs)
	globalLogChecker := NewLogChecker(logs)

	pu, err := userLogChecker.GetUserOccurrenceRate(logs)

	if err != nil {
		return 0, err
	}

	if pu == 0 {
		return 1e10, nil
	}

	puA := 1.0 / float64(userLogChecker.totalCount)

	result := 0.0

	probabilities := make(map[string]probability)

	for _, feature := range config.Features {
		pxu, err := userLogChecker.GetOccurrenceRateUser(attempt, feature)
		if err != nil {
			return 0, err
		}

		px, err := globalLogChecker.GetOccurrenceRateUser(attempt, feature)
		if err != nil {
			return 0, err
		}

		probabilities[feature] = probability{px, pxu}
	}

	rList := make(map[string]float64)

	for feature, prob := range probabilities {
		w := Weights[feature]
		r := 1 - (0.05*prob.px*puA)/(prob.pxu*pu)
		rList[feature] = r
		result += w * r
	}

	updateWeights(rList)

	return result, nil
}

func updateSub(tReduce []string, wMin float64, lambda float64) {
	ends := 0.0

	for _, feature := range tReduce {
		original := Weights[feature]
		Weights[feature] = (1-lambda)*Weights[feature] + lambda*wMin
		ends += original - Weights[feature]
	}

	if ends > 0 {
		for _, feature := range config.Features {
			Weights[feature] += ends / float64(len(config.Features))
		}
	}
}

func updateWeights(rList map[string]float64) {
	tau := config.Configuration.UpdateParameters.Tau
	lambda := config.Configuration.UpdateParameters.Lambda

	tReduce := make([]string, 0, 5)

	for feature, r := range rList {
		if r < tau {
			tReduce = append(tReduce, feature)
		}
	}

	wMin := math.Min((1.0-tau)/4.0, 1.0/5.0)

	updateSub(tReduce, wMin, lambda)
}
