package aicatalog

import (
	"strings"
	"testing"
)

// THE WHOLE POINT OF THIS PACKAGE IS THAT NOBODY TYPES A DOMAIN, so the domains
// in it have to be right in a way a typed one never had to be: a hole here is a
// hole on every fleet at once, and it looks exactly like an assistant nobody
// uses.
func TestEveryEntryIsUsable(t *testing.T) {
	seenID := map[string]string{}
	seenDomain := map[string]string{}

	for _, a := range All() {
		if a.ID == "" || a.Name == "" {
			t.Fatalf("an entry has no id or no name: %+v", a)
		}
		if prev, dup := seenID[a.ID]; dup {
			t.Errorf("%q is the id of both %s and %s, so one of them can never be saved", a.ID, prev, a.Name)
		}
		seenID[a.ID] = a.Name

		if len(a.Domains) == 0 {
			t.Errorf("%s watches nothing", a.Name)
		}
		for _, d := range a.Domains {
			if d != normalise(d) {
				t.Errorf("%s carries %q, which is not a bare hostname: matching is on the host", a.Name, d)
			}
			// A PATH IS NOT A HOST. Bing's chat and GitHub Copilot both live at
			// a path, and listing either means watching the whole site - which
			// is a far larger decision than the one somebody thinks they are
			// making when they switch on an assistant.
			if strings.ContainsAny(d, "/?#*") {
				t.Errorf("%s carries %q: a path cannot be matched and would have to become the whole site", a.Name, d)
			}
			if !strings.Contains(d, ".") {
				t.Errorf("%s carries %q, which is not a domain", a.Name, d)
			}
			if prev, dup := seenDomain[d]; dup {
				// Two entries sharing a host means two rules fighting over the
				// same traffic, and which one wins is whichever the policy
				// sorted first.
				t.Errorf("%q belongs to both %s and %s", d, prev, a.Name)
			}
			seenDomain[d] = a.Name
		}
	}
}

// A saved rule finds its way back to the entry it came from, whatever somebody
// called it. The name is typing; the domains are the rule.
func TestASavedRuleIsRecognisedByItsDomains(t *testing.T) {
	cases := []struct {
		domains []string
		want    string
	}{
		{[]string{"chatgpt.com", "chat.openai.com"}, "chatgpt"},
		{[]string{"chat.openai.com"}, "chatgpt"},   // the old host alone
		{[]string{"CHATGPT.COM"}, "chatgpt"},       // typed in caps
		{[]string{"https://claude.ai/"}, "claude"}, // pasted from the address bar
		{[]string{"*.claude.ai"}, "claude"},        // written as a wildcard
		{[]string{"aistudio.google.com"}, "gemini"},
	}
	for _, c := range cases {
		got, ok := Match(c.domains)
		if !ok || got.ID != c.want {
			t.Errorf("%v was read as %q, want %q", c.domains, got.ID, c.want)
		}
	}

	// And something nobody ships stays custom rather than being folded into a
	// built-in rule that watches different hosts.
	if a, ok := Match([]string{"llm.internal.example"}); ok {
		t.Errorf("an internal host was matched to %s", a.Name)
	}
}

// The default is the general assistants and nothing else.
//
// A first week that starts recording everything anybody does on Replit or
// Hugging Face is this product making a decision on somebody's behalf on the
// day they installed it. Those are whole sites with an assistant inside them.
func TestTheDefaultIsTheAssistantsAndNotTheWholeList(t *testing.T) {
	def := Default()
	if len(def) == 0 {
		t.Fatal("a project would start watching nothing, so its first week is an empty page")
	}
	for _, a := range def {
		if a.Group != GroupChat {
			t.Errorf("%s is on by default and it is a %s", a.Name, a.Group)
		}
		if a.Note != "" {
			// A note exists to warn somebody before they switch a thing on.
			// Switching it on for them and leaving the warning is worse than
			// either.
			t.Errorf("%s is on by default and carries a warning: %q", a.Name, a.Note)
		}
	}
	if len(def) >= len(All()) {
		t.Error("everything is on by default, so the groups below the assistants mean nothing")
	}
}

// Every group in the list is one the dashboard draws, and every group the
// dashboard draws has something in it. A group missing from Groups is a section
// of the catalogue nobody can reach.
func TestNoAssistantIsInAGroupNothingDraws(t *testing.T) {
	drawn := map[Group]bool{}
	for _, g := range Groups {
		if len(InGroup(g)) == 0 {
			t.Errorf("the %s section is empty", g)
		}
		drawn[g] = true
	}
	for _, a := range All() {
		if !drawn[a.Group] {
			t.Errorf("%s is in group %q, which is never shown", a.Name, a.Group)
		}
	}
}

// The list is a copy. A caller that sorts it in place would reorder it for
// everybody, and a settings page is exactly where somebody sorts a list.
func TestTheListCannotBeEditedByItsReaders(t *testing.T) {
	first := All()[0].Name
	got := All()
	got[0].Name = "changed"
	if All()[0].Name != first {
		t.Fatal("editing the returned list changed the catalogue")
	}
}
