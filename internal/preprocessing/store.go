package preprocessing

import (
	"database/sql"
)

// 插入日志数据
func StoreLog(db *sql.DB, log LogEntry) error {
	_, err := db.Exec(
		"INSERT INTO logs (userid, gid, logtime, objectivesystem, loginip, browserfingerprinting, country, regionname, city, isp, org, as, agent, browsername, browserversion, osname, osversion, devicetype, fonts, devicememory, hardwareconcurrency, timezone, cpuclass, platform) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		log.UserID,
		log.GID,
		log.LogTime,
		log.ObjectiveSystem,
		log.LoginIP,
		log.BrowserFingerprinting,
		log.Country,
		log.RegionName,
		log.City,
		log.ISP,
		log.Org,
		log.AS,
		log.Agent,
		log.BrowserName,
		log.BrowserVersion,
		log.OSName,
		log.OSVersion,
		log.DeviceType,
		log.Fonts,
		log.DeviceMemory,
		log.HardwareConcurrency,
		log.Timezone,
		log.CpuClass,
		log.Platform,
	)
	return err
}

func StoreLogBatch(db *sql.DB, logs []LogEntry) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(
		"INSERT INTO logs (userid, gid, logtime, objectivesystem, loginip, browserfingerprinting, country, regionname, city, isp, org, as, agent, browsername, browserversion, osname, osversion, devicetype, fonts, devicememory, hardwareconcurrency, timezone, cpuclass, platform) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
	)

	if err != nil {
		return err
	}

	for _, log := range logs {
		_, err = stmt.Exec(
			log.UserID,
			log.GID,
			log.LogTime,
			log.ObjectiveSystem,
			log.LoginIP,
			log.BrowserFingerprinting,
			log.Country,
			log.RegionName,
			log.City,
			log.ISP,
			log.Org,
			log.AS,
			log.Agent,
			log.BrowserName,
			log.BrowserVersion,
			log.OSName,
			log.OSVersion,
			log.DeviceType,
			log.Fonts,
			log.DeviceMemory,
			log.HardwareConcurrency,
			log.Timezone,
			log.CpuClass,
			log.Platform,
		)
		if err != nil {
			return err
		}
	}

	err = tx.Commit()
	if err != nil {
		return err
	}

	return nil
}
