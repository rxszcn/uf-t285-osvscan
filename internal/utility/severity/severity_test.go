package severity_test

import (
	"math"
	"testing"

	"github.com/google/osv-scanner/v2/internal/grouper"
	"github.com/google/osv-scanner/v2/internal/utility/severity"
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

func TestSeverity_CalculateScore(t *testing.T) {
	t.Parallel()

	type result struct {
		score  float64
		rating string
	}
	tests := []struct {
		name string
		sev  *osvschema.Severity
		want result
	}{
		{
			name: "Empty_Severity_Type",
			sev:  &osvschema.Severity{},
			want: result{
				score:  -1,
				rating: "UNKNOWN",
			},
		},
		{
			name: "CVSS_v2.0",
			sev: &osvschema.Severity{
				Type:  osvschema.Severity_CVSS_V2,
				Score: "AV:L/AC:M/Au:N/C:N/I:P/A:C/E:H/RL:U/RC:C/CDP:LM/TD:M/CR:L/IR:M/AR:H",
			},
			want: result{
				score:  5.4,
				rating: "MEDIUM",
			},
		},
		{
			name: "CVSS_v3.0",
			sev: &osvschema.Severity{
				Type:  osvschema.Severity_CVSS_V3,
				Score: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:U/RL:T/RC:U/CR:L/IR:L/AR:H/MAV:P/MAC:H/MPR:H/MUI:R/MS:C/MC:H/MI:H/MA:H",
			},
			want: result{
				score:  10.0,
				rating: "CRITICAL",
			},
		},
		{
			name: "CVSS_v3.1",
			sev: &osvschema.Severity{
				Type:  osvschema.Severity_CVSS_V3,
				Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:U/RL:T/RC:U/CR:L/IR:L/AR:H/MAV:P/MAC:H/MPR:H/MUI:R/MS:C/MC:H/MI:H/MA:H",
			},
			want: result{
				score:  10.0,
				rating: "CRITICAL",
			},
		},
		{
			name: "CVSS_v4.0",
			sev: &osvschema.Severity{
				Type:  osvschema.Severity_CVSS_V4,
				Score: "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/S:N/AU:N/R:A/V:D/RE:L/U:Clear",
			},
			want: result{
				score:  0.0,
				rating: "NONE",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			gotScore, gotRating, err := severity.CalculateScore(tt.sev)
			if err != nil {
				t.Errorf("CalculateScore() error: %v", err)
			}
			// CVSS scores are only supposed to be to 1 decimal place.
			// Multiply and round to get around potential precision issues.
			if math.Round(10*gotScore) != math.Round(10*tt.want.score) || gotRating != tt.want.rating {
				t.Errorf("CalculateScore() = (%.1f, %s), want (%.1f, %s)", gotScore, gotRating, tt.want.score, tt.want.rating)
			}
		})
	}
}

// severityFixtureVectors returns the two score vectors shared by the
// multi-vector aggregation fixtures: one well-formed CVSS 3.1 vector that
// scores 8.8, and one malformed vector (invalid "A" metric value) that the
// CVSS parser rejects.
func severityFixtureVectors() (string, string) {
	return "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:X"
}

// severityFixtureRecords builds the two in-memory vulnerability records used by
// the aggregation tests, so they can be reproduced without any external data:
//
//   - "OSV-MIXED" carries both the well-formed and the malformed vector;
//   - "OSV-MALFORMED" carries only the malformed vector.
func severityFixtureRecords() []*osvschema.Vulnerability {
	valid, malformed := severityFixtureVectors()

	return []*osvschema.Vulnerability{
		{
			Id: "OSV-MIXED",
			Severity: []*osvschema.Severity{
				{Type: osvschema.Severity_CVSS_V3, Score: valid},
				{Type: osvschema.Severity_CVSS_V3, Score: malformed},
			},
		},
		{
			Id: "OSV-MALFORMED",
			Severity: []*osvschema.Severity{
				{Type: osvschema.Severity_CVSS_V3, Score: malformed},
			},
		},
	}
}

func TestSeverity_CalculateOverallScore(t *testing.T) {
	t.Parallel()

	valid, malformed := severityFixtureVectors()

	fixtures := map[string]*osvschema.Vulnerability{}
	for _, vuln := range severityFixtureRecords() {
		fixtures[vuln.GetId()] = vuln
	}

	tests := []struct {
		name string
		// vuln is one of the constructed fixture records, when the case is
		// defined in terms of a whole record rather than a bare vector list
		vuln          *osvschema.Vulnerability
		severities    []*osvschema.Severity
		wantScore     float64
		wantRating    string
		wantErr       bool
		wantGroupSevs string
	}{
		{
			name: "no_severities",
			// no severity entries at all keeps the existing unknown convention
			severities:    nil,
			wantScore:     -1,
			wantRating:    "UNKNOWN",
			wantGroupSevs: "",
		},
		{
			// a single malformed vector must not produce a score, and the
			// group level reading stays at the existing unknown convention
			name:          "only_a_malformed_vector",
			vuln:          fixtures["OSV-MALFORMED"],
			wantScore:     -1,
			wantRating:    "UNKNOWN",
			wantErr:       true,
			wantGroupSevs: "",
		},
		{
			// the malformed vector must not swallow the score of the
			// well-formed vector carried by the same record: the group level
			// reading equals the score of that single parsable vector
			name:          "valid_vector_mixed_with_a_malformed_vector",
			vuln:          fixtures["OSV-MIXED"],
			wantScore:     8.8,
			wantRating:    "HIGH",
			wantGroupSevs: "8.8",
		},
		{
			// the record is still usable when the malformed vector comes first
			name: "malformed_vector_before_a_valid_vector",
			severities: []*osvschema.Severity{
				{Type: osvschema.Severity_CVSS_V3, Score: malformed},
				{Type: osvschema.Severity_CVSS_V3, Score: valid},
			},
			wantScore:     8.8,
			wantRating:    "HIGH",
			wantGroupSevs: "8.8",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			severities := tt.severities
			if tt.vuln != nil {
				severities = tt.vuln.GetSeverity()
			}

			gotScore, gotRating, err := severity.CalculateOverallScore(severities)
			if (err != nil) != tt.wantErr {
				t.Errorf("CalculateOverallScore() error = %v, wantErr %v", err, tt.wantErr)
			}
			if math.Round(10*gotScore) != math.Round(10*tt.wantScore) || gotRating != tt.wantRating {
				t.Errorf("CalculateOverallScore() = (%.1f, %s), want (%.1f, %s)", gotScore, gotRating, tt.wantScore, tt.wantRating)
			}

			// the same reading, taken from the group severity precomputed by
			// the grouper for the record that carries these vectors
			vuln := tt.vuln
			if vuln == nil {
				vuln = &osvschema.Vulnerability{Id: "OSV-INLINE", Severity: severities}
			}

			groups := grouper.Build(models.PackageVulns{
				Package:         models.PackageInfo{Name: "fixture-pkg", Version: "1.0.0", Ecosystem: "npm"},
				Vulnerabilities: []*osvschema.Vulnerability{vuln},
			}, false)
			if len(groups) != 1 {
				t.Fatalf("expected a single vulnerability group, got %d", len(groups))
			}
			if groups[0].MaxSeverity != tt.wantGroupSevs {
				t.Errorf("group MaxSeverity = %q, want %q", groups[0].MaxSeverity, tt.wantGroupSevs)
			}
		})
	}
}

func TestSeverity_FindUbuntuSeverity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		severities []*osvschema.Severity
		want       string
	}{
		{
			name:       "no_severities",
			severities: nil,
			want:       "",
		},
		{
			name: "no_ubuntu_severity",
			severities: []*osvschema.Severity{
				{Type: osvschema.Severity_CVSS_V3, Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"},
			},
			want: "",
		},
		{
			name: "one_ubuntu_severity",
			severities: []*osvschema.Severity{
				{Type: osvschema.Severity_CVSS_V3, Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"},
				{Type: osvschema.Severity_Ubuntu, Score: "medium"},
			},
			want: "medium",
		},
		{
			// a record should only have one ubuntu priority, but if there are
			// multiple then the first one is used rather than the highest
			name: "multiple_ubuntu_severities",
			severities: []*osvschema.Severity{
				{Type: osvschema.Severity_Ubuntu, Score: "low"},
				{Type: osvschema.Severity_Ubuntu, Score: "critical"},
			},
			want: "low",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := severity.FindUbuntuSeverity(tt.severities); got != tt.want {
				t.Errorf("FindUbuntuSeverity() = %q, want %q", got, tt.want)
			}
		})
	}
}
