// Description: This file contains the store package which is responsible for managing the state of the application.
package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"

	_ "github.com/go-sql-driver/mysql"
)

type LogChecker struct {
	ipMap                  map[string]int `json:"ipMap"`
	ispMap                 map[string]int `json:"ispMap"`
	regionMap              map[string]int `json:"regionMap"`
	browserNameMap         map[string]int `json:"browserNameMap"`
	browserVersionMap      map[string]int `json:"browserVersionMap"`
	osNameMap              map[string]int `json:"osNameMap"`
	osVersionMap           map[string]int `json:"osVersionMap"`
	fontsMap               map[string]int `json:"fontsMap"`
	deviceMemoryMap        map[string]int `json:"deviceMemoryMap"`
	hardwareConcurrencyMap map[string]int `json:"hardwareConcurrencyMap"`
	timezoneMap            map[string]int `json:"timezoneMap"`
	cpuClassMap            map[string]int `json:"cpuClassMap"`
	platformMap            map[string]int `json:"platformMap"`
	totalCount             int            `json:"totalCount"`
}

func main() {
	db, err := sql.Open("mysql", "root:password@tcp(127.0.0.1:3306)/testdb")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	err = db.Ping()
	if err != nil {
		log.Fatal(err)
	}

	testentry := LogChecker{
		ipMap:                  make(map[string]int),
		ispMap:                 make(map[string]int),
		regionMap:              make(map[string]int),
		browserNameMap:         make(map[string]int),
		browserVersionMap:      make(map[string]int),
		osNameMap:              make(map[string]int),
		osVersionMap:           make(map[string]int),
		fontsMap:               make(map[string]int),
		deviceMemoryMap:        make(map[string]int),
		hardwareConcurrencyMap: make(map[string]int),
		timezoneMap:            make(map[string]int),
		cpuClassMap:            make(map[string]int),
		platformMap:            make(map[string]int),
		totalCount:             0,
	}

	testentry.ipMap["1.1.1.1"] = 5
	testentry.ipMap["2.2.2.2"] = 19
	testentry.ispMap["isp1"] = 5
	testentry.regionMap["region1"] = 5
	testentry.browserNameMap["browser1"] = 6
	testentry.browserVersionMap["version1"] = 6

	jsonData, err := json.Marshal(testentry)
	if err != nil {
		log.Fatal(err)
	}

	insertQuery := fmt.Sprintf("INSERT INTO logchecker (data) VALUES ('%s')", string(jsonData))
	_, err = db.Exec(insertQuery)

	if err != nil {
		log.Fatal(err)
	}
}
