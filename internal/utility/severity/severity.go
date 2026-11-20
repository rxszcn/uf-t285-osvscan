// Package severity provides functionality for calculating vulnerability severity.
package severity

import (
	"errors"
	"slices"
	"strconv"
	"strings"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
	gocvss20 "github.com/pandatix/go-cvss/20"
	gocvss30 "github.com/pandatix/go-cvss/30"
	gocvss31 "github.com/pandatix/go-cvss/31"
	gocvss40 "github.com/pandatix/go-cvss/40"
)

// Rating represents the severity level of a vulnerability.
type Rating string

const (
	CriticalRating Rating = "CRITICAL"
	HighRating     Rating = "HIGH"
	MediumRating   Rating = "MEDIUM"
	LowRating      Rating = "LOW"
	UnknownRating  Rating = "UNKNOWN"
)

func CalculateScore(severity *osvschema.Severity) (float64, string, error) {
	score := -1.0
	rating := string(UnknownRating)
	var err error
	switch severity.GetType() {
	case osvschema.Severity_UNSPECIFIED:
		// UNSPECIFIED has no score information
	case osvschema.Severity_CVSS_V2:
		var vec *gocvss20.CVSS20
		vec, err = gocvss20.ParseVector(severity.GetScore())
		if err == nil {
			score = vec.BaseScore()
			// CVSS 2.0 does not define a rating, use CVSS 3.0's rating instead
			rating, err = gocvss30.Rating(score)
		}
	case osvschema.Severity_CVSS_V3:
		switch {
		case strings.HasPrefix(severity.GetScore(), "CVSS:3.0"):
			var vec *gocvss30.CVSS30
			vec, err = gocvss30.ParseVector(severity.GetScore())
			if err == nil {
				score = vec.BaseScore()
				rating, err = gocvss30.Rating(score)
			}
		case strings.HasPrefix(severity.GetScore(), "CVSS:3.1"):
			var vec *gocvss31.CVSS31
			vec, err = gocvss31.ParseVector(severity.GetScore())
			if err == nil {
				score = vec.BaseScore()
				rating, err = gocvss31.Rating(score)
			}
		}
	case osvschema.Severity_CVSS_V4:
		var vec *gocvss40.CVSS40
		vec, err = gocvss40.ParseVector(severity.GetScore())
		if err == nil {
			score = vec.Score()
			rating, err = gocvss40.Rating(score)
		}
	case osvschema.Severity_Ubuntu:
		rating = severity.GetScore()
	}

	return score, rating, err
}

// CalculateOverallScore returns the highest score and its rating across all
// severity entries of a record.
//
// An entry that cannot be parsed is skipped instead of aborting the whole
// aggregation, so a single malformed vector can no longer discard the score
// of the other, well-formed vectors carried by the same record. The parse
// errors are only reported when no entry yielded a usable score at all, in
// which case the result stays at the unknown (-1, "UNKNOWN") convention.
func CalculateOverallScore(severities []*osvschema.Severity) (float64, string, error) {
	maxScore := -1.0
	maxRating := string(UnknownRating)
	var errs []error

	for _, severity := range severities {
		score, rating, err := CalculateScore(severity)
		if err != nil {
			errs = append(errs, err)

			continue
		}
		if score > maxScore {
			maxScore = score
			maxRating = rating
		}
	}

	if maxScore < 0 && len(errs) > 0 {
		return -1, string(UnknownRating), errors.Join(errs...)
	}

	return maxScore, maxRating, nil
}

func CalculateRating(score string) (Rating, error) {
	// All CSVs' rating methods are identical.
	parsedScore, err := strconv.ParseFloat(score, 64)
	if err != nil {
		return UnknownRating, err
	}

	rating, err := gocvss30.Rating(parsedScore)
	if err != nil || rating == "NONE" {
		rating = string(UnknownRating)
	}

	return Rating(rating), err
}

var ubuntuPriorities = []string{"negligible", "low", "medium", "high", "critical"}

func MaxUbuntuPriority(a, b string) string {
	if slices.Index(ubuntuPriorities, b) > slices.Index(ubuntuPriorities, a) {
		return b
	}

	return a
}

func FindUbuntuSeverity(severities []*osvschema.Severity) string {
	for _, sev := range severities {
		if sev.GetType() == osvschema.Severity_Ubuntu {
			return sev.GetScore()
		}
	}

	return ""
}
