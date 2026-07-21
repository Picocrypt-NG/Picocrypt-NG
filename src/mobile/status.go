package mobile

import (
	"math"
	"regexp"
	"strconv"
)

type classifiedStatus struct {
	Code              string
	SpeedMiBPerSecond float64
	ETA               string
}

type classifiedInfo struct {
	Code    string
	Current int64
	Total   int64
}

var staticStatusCodes = map[string]string{ //nolint:gosec // G101: status phrases and stable UI codes are not credentials.
	"Starting...":           "STARTING",
	"Completed":             "COMPLETED",
	"Cancelled":             "CANCELLED",
	"Error":                 "ERROR",
	"Compressing files...":  "COMPRESSING_FILES",
	"Generating values...":  "GENERATING_VALUES",
	"Deriving key...":       "DERIVING_KEY",
	"Reading keyfiles...":   "READING_KEYFILES",
	"Calculating values...": "CALCULATING_VALUES",
	"Writing values...":     "WRITING_VALUES",
	"Splitting...":          "SPLITTING",
	"Recombining chunks...": "RECOMBINING_CHUNKS",
	"Reading values...":     "READING_VALUES",
	"Warning: duplicate keyfiles detected (keys cancel out)...": "DUPLICATE_KEYFILES_WARNING",
	"Verifying integrity (pass 1 of 2)...":                      "VERIFYING_INTEGRITY",
	"MAC verification failed, continuing anyway...":             "MAC_VERIFICATION_FAILED_CONTINUING",
	"Repairing (verifying)...":                                  "REPAIRING_VERIFYING",
	"Integrity verified, decrypting...":                         "INTEGRITY_VERIFIED_DECRYPTING",
	"Comparing values...":                                       "COMPARING_VALUES",
	"Unzipping...":                                              "UNZIPPING",
	"Adding plausible deniability...":                           "ADDING_PLAUSIBLE_DENIABILITY",
	"Removing deniability protection...":                        "REMOVING_DENIABILITY_PROTECTION",
}

var rateStatusCodes = map[string]string{
	"Compressing at":          "COMPRESSING_RATE",
	"Encrypting at":           "ENCRYPTING_RATE",
	"Splitting at":            "SPLITTING_RATE",
	"Recombining at":          "RECOMBINING_RATE",
	"Verifying at":            "VERIFYING_RATE",
	"Decrypting at":           "DECRYPTING_RATE",
	"Repairing at":            "REPAIRING_RATE",
	"Unpacking at":            "UNPACKING_RATE",
	"Adding deniability at":   "ADDING_DENIABILITY_RATE",
	"Removing deniability at": "REMOVING_DENIABILITY_RATE",
}

var (
	rateStatusPattern  = regexp.MustCompile(`^(Compressing at|Encrypting at|Splitting at|Recombining at|Verifying at|Decrypting at|Repairing at|Unpacking at|Adding deniability at|Removing deniability at) (-?[0-9]+\.[0-9]{2}|[+-]Inf|NaN) MiB/s \(ETA: ([0-9]{2,}:[0-9]{2}:[0-9]{2})\)$`)
	etaPattern         = regexp.MustCompile(`^([0-9]{2,}):([0-9]{2}):([0-9]{2})$`)
	percentInfoPattern = regexp.MustCompile(`^[0-9]+\.[0-9]{2}%( \(verifying\))?$`)
	itemInfoPattern    = regexp.MustCompile(`^([0-9]+)/([0-9]+)$`)
)

func classifyStatus(text string) classifiedStatus {
	if text == "" {
		return classifiedStatus{Code: "NONE"}
	}
	if code, ok := staticStatusCodes[text]; ok {
		return classifiedStatus{Code: code}
	}

	matches := rateStatusPattern.FindStringSubmatch(text)
	if len(matches) != 4 {
		return classifiedStatus{Code: "UNKNOWN"}
	}

	speed, err := strconv.ParseFloat(matches[2], 64)
	if err != nil || math.IsNaN(speed) || math.IsInf(speed, 0) || speed < 0 {
		return classifiedStatus{Code: "UNKNOWN"}
	}
	etaMatches := etaPattern.FindStringSubmatch(matches[3])
	if len(etaMatches) != 4 {
		return classifiedStatus{Code: "UNKNOWN"}
	}
	minute, err := strconv.Atoi(etaMatches[2])
	if err != nil || minute > 59 {
		return classifiedStatus{Code: "UNKNOWN"}
	}
	second, err := strconv.Atoi(etaMatches[3])
	if err != nil || second > 59 {
		return classifiedStatus{Code: "UNKNOWN"}
	}

	return classifiedStatus{
		Code:              rateStatusCodes[matches[1]],
		SpeedMiBPerSecond: speed,
		ETA:               matches[3],
	}
}

func classifyInfo(text string) classifiedInfo {
	if text == "" {
		return classifiedInfo{Code: "NONE"}
	}
	if percentInfoPattern.MatchString(text) {
		return classifiedInfo{Code: "PERCENT"}
	}

	matches := itemInfoPattern.FindStringSubmatch(text)
	if len(matches) != 3 {
		return classifiedInfo{Code: "UNKNOWN"}
	}
	current, err := strconv.ParseInt(matches[1], 10, 64)
	if err != nil {
		return classifiedInfo{Code: "UNKNOWN"}
	}
	total, err := strconv.ParseInt(matches[2], 10, 64)
	if err != nil {
		return classifiedInfo{Code: "UNKNOWN"}
	}

	return classifiedInfo{Code: "ITEM_COUNT", Current: current, Total: total}
}
