package commands

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/codeyevsky/solongate/proxy/internal/api"
)

func rulesFrom(t *testing.T, raw string) api.Rules {
	t.Helper()
	var r api.Rules
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		t.Fatal(err)
	}
	return r
}

// Disabling a rule must not narrow it to the fields this build models. A rule
// editor in a newer dashboard is exactly what puts an unknown field on one, and
// rewriting the array through PolicyRule would drop it silently.
func TestSetRuleEnabledKeepsFieldsThisBuildDoesNotKnow(t *testing.T) {
	pol := api.PolicySet{ID: "p", Name: "P", Rules: rulesFrom(t, `[
		{"id":"r1","effect":"DENY","enabled":true,"somethingNewer":{"a":1},
		 "pathConstraints":{"denied":["*secrets*"]}},
		{"id":"r2","effect":"DENY","enabled":true}
	]`)}

	next, found := setRuleEnabled(pol, "r1", false)
	if !found {
		t.Fatal("r1 is in the policy")
	}
	encoded, err := json.Marshal(next.Rules)
	if err != nil {
		t.Fatal(err)
	}
	got := string(encoded)

	if !strings.Contains(got, `"somethingNewer"`) {
		t.Errorf("a field this build does not model was dropped: %s", got)
	}
	if !strings.Contains(got, `"enabled":false`) {
		t.Errorf("the flag was not flipped: %s", got)
	}
	// Only the named rule moves.
	if strings.Count(got, `"enabled":false`) != 1 {
		t.Errorf("more than one rule changed: %s", got)
	}
	if !strings.Contains(got, `"*secrets*"`) {
		t.Errorf("the constraint was lost: %s", got)
	}
}

func TestSetRuleEnabledReportsARuleThatIsNotThere(t *testing.T) {
	pol := api.PolicySet{Rules: rulesFrom(t, `[{"id":"r1","enabled":true}]`)}
	if _, found := setRuleEnabled(pol, "nope", false); found {
		t.Error("a rule that is not in the policy must not report as found")
	}
}

func TestSetRuleEnabledTurnsARuleBackOn(t *testing.T) {
	pol := api.PolicySet{Rules: rulesFrom(t, `[{"id":"r1","enabled":false}]`)}
	next, found := setRuleEnabled(pol, "r1", true)
	if !found {
		t.Fatal("r1 is in the policy")
	}
	encoded, _ := json.Marshal(next.Rules)
	if !strings.Contains(string(encoded), `"enabled":true`) {
		t.Errorf("not re-enabled: %s", encoded)
	}
}
