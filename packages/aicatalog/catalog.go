// Package aicatalog is the list of AI assistants this product knows, and the
// hostnames each one actually answers on.
//
// IT EXISTS SO THAT NOBODY TYPES A DOMAIN. The DLP screen used to be a form
// where a person wrote "ChatGPT" in one box and "chat.openai.com, chatgpt.com"
// in another, and every part of that is a way to get it wrong: chatgpt.com
// alone misses the older host, gemini.google.com alone misses AI Studio, and a
// typo produces a rule that silently matches nothing at all. A watch list with
// a hole in it looks exactly like a watch list with nothing to report.
//
// So the product ships the list and the person picks from it. What they choose
// is what happens on each assistant, which is the only part that is theirs.
//
// HOSTS ONLY, NEVER PATHS. Matching is on the hostname (see shadowpolicy/host.go
// for why, and for what a naive Contains gets wrong), so an assistant that lives
// at a path on somebody else's domain cannot be listed here as itself. Bing's
// chat at bing.com/chat and GitHub Copilot at github.com/copilot are the two
// that hurt: listing them means watching all of Bing and all of GitHub, which
// is a different and much larger decision than "watch Copilot", and it is not
// one this list makes on anybody's behalf.
//
// The domains are the ASSISTANT's, not the vendor's. openai.com is a company
// website with a blog on it; chatgpt.com is where somebody pastes a customer
// list. A rule on the first would fire on somebody reading release notes.
package aicatalog

import "strings"

// Group is how the list is broken up on screen. It is presentation, but it is
// here rather than in the dashboard because the grouping is a property of what
// these things ARE - a coding tool and a general assistant leak differently -
// and two products showing the same list in different orders is two products.
type Group string

const (
	// GroupChat is the general assistants: a box, a person, and whatever they
	// paste into it. This is where this product earns its keep.
	GroupChat Group = "Assistants"
	// GroupCoding is the ones people work in rather than ask: source, stack
	// traces, config, and the credentials that live in all three.
	GroupCoding Group = "Coding"
	// GroupSearch is answer engines. Shorter prompts, and the leak is usually
	// somebody checking whether a real customer's details look right.
	GroupSearch Group = "Search"
	// GroupPlayground is the model consoles: an API key in a box by design, and
	// whatever is being tested pasted in beside it.
	GroupPlayground Group = "Playgrounds"
)

// Assistant is one entry.
type Assistant struct {
	// ID is the stable name this is stored and matched by. It never changes,
	// even when the product is renamed, because a saved policy refers to it.
	ID string
	// Name is what the product calls itself today.
	Name string
	// Domains is every hostname it answers on. A rule covers a host and every
	// subdomain of it.
	Domains []string
	Group   Group
	// Desc is a few words on what this assistant IS - whose it is, or what it is
	// for - so a card can say more than its name. Kept short: it sits under a
	// logo, not in a paragraph.
	Desc string
	// Note is the one thing worth knowing before switching this on, or empty
	// when there is nothing. It is the difference between a domain that is only
	// ever the assistant and one that carries other things too.
	Note string

	// Soon is an assistant this product KNOWS ABOUT and does not watch yet.
	//
	// It stays on the list rather than being deleted from it, and that is the
	// whole point of the flag. A shipped list is also a claim about coverage: an
	// operator scanning it counts what is there and assumes the rest does not
	// exist, so an assistant quietly missing is a gap nobody can see. One that
	// is present and says "coming soon" is a gap they can plan around - and it
	// is the honest answer to "does SolonGate watch Grok", which is yes, not
	// yet, rather than silence.
	//
	// It carries no rule and cannot be given one. The card does not open, the
	// save never writes a site for it, and nothing about its domains reaches a
	// browser: a switch that looks live and enforces nothing is worse than no
	// switch, because somebody sets it and stops worrying.
	Soon bool
}

// all is the catalogue.
//
// ORDER IS DELIBERATE within each group: the ones a fleet actually uses first,
// because a list of thirty where the first five are the answer is a list
// somebody scrolls past. Alphabetical would put Character.AI above ChatGPT.
//
// AND THE ONES THIS PRODUCT ACTUALLY WATCHES COME FIRST INSIDE THAT. Half the
// chat list is Soon, and a grid that interleaves the five live ones with seven
// that cannot be switched on is a grid where the working half is something you
// hunt for. ChatGPT, Gemini, Claude, DeepSeek, Le Chat, and then the rest.
var all = []Assistant{
	// ── the general assistants ──────────────────────────────────────────────
	{
		ID: "chatgpt", Name: "ChatGPT", Group: GroupChat, Desc: "OpenAI's general assistant",
		// chat.openai.com still resolves and still redirects, and a fleet with
		// an old bookmark or a pinned tab is a fleet that never touches the new
		// host. Dropping it is a silent hole.
		Domains: []string{"chatgpt.com", "chat.openai.com"},
	},
	{
		ID: "gemini", Name: "Gemini", Group: GroupChat, Desc: "Google's chat assistant",
		// AI Studio is the same models with a key box beside them, and it is
		// where the pasting that matters tends to happen.
		Domains: []string{"gemini.google.com", "aistudio.google.com"},
	},
	{
		ID: "claude", Name: "Claude", Group: GroupChat, Desc: "Anthropic's chat assistant",
		Domains: []string{"claude.ai"},
	},
	{
		ID: "deepseek", Name: "DeepSeek", Group: GroupChat, Desc: "DeepSeek's reasoning chat",
		Domains: []string{"chat.deepseek.com"},
	},
	{
		ID: "mistral", Name: "Le Chat (Mistral)", Group: GroupChat, Desc: "Mistral's Le Chat",
		Domains: []string{"chat.mistral.ai"},
	},
	{
		ID: "copilot", Name: "Microsoft Copilot", Group: GroupChat, Desc: "Microsoft's work assistant",
		Soon: true,
		// The standalone assistant only. Copilot inside Microsoft 365 lives on
		// m365.cloud.microsoft, which is also Word, Excel and Outlook on the
		// web - watching it to catch Copilot means watching everything anybody
		// writes in a document all day, which is a different product. It is
		// left out rather than listed with a warning: an entry that is on by
		// default and carries a warning is a warning nobody reads in time.
		Domains: []string{"copilot.microsoft.com"},
	},
	{
		ID: "grok", Name: "Grok", Group: GroupChat, Desc: "xAI's chat assistant",
		Soon: true,
		// Not x.com: Grok lives at a path there, and a rule on x.com is a rule
		// on the whole of X.
		Domains: []string{"grok.com"},
	},
	{
		ID: "metaai", Name: "Meta AI", Group: GroupChat, Desc: "Meta's chat assistant",
		Soon:    true,
		Domains: []string{"meta.ai"},
	},
	{
		ID: "qwen", Name: "Qwen", Group: GroupChat, Desc: "Alibaba's Qwen chat",
		Soon:    true,
		Domains: []string{"chat.qwen.ai", "tongyi.aliyun.com"},
	},
	{
		ID: "kimi", Name: "Kimi", Group: GroupChat, Desc: "Moonshot's long-context chat",
		Soon:    true,
		Domains: []string{"kimi.moonshot.cn", "kimi.com"},
	},
	{
		ID: "poe", Name: "Poe", Group: GroupChat, Desc: "Quora's multi-model chat",
		Soon:    true,
		Domains: []string{"poe.com"},
	},
	{
		ID: "characterai", Name: "Character.AI", Group: GroupChat, Desc: "Roleplay character chatbots",
		Soon:    true,
		Domains: []string{"character.ai"},
	},

	// ── the ones people work in ─────────────────────────────────────────────
	{
		ID: "v0", Name: "v0", Group: GroupCoding, Desc: "Vercel's UI generator",
		Soon:    true,
		Domains: []string{"v0.dev", "v0.app"},
	},
	{
		ID: "lovable", Name: "Lovable", Group: GroupCoding, Desc: "Prompt-to-app builder",
		Soon:    true,
		Domains: []string{"lovable.dev"},
	},
	{
		ID: "bolt", Name: "Bolt", Group: GroupCoding, Desc: "In-browser app builder",
		Soon:    true,
		Domains: []string{"bolt.new"},
	},
	{
		ID: "replit", Name: "Replit", Group: GroupCoding, Desc: "Cloud IDE with an agent",
		Soon:    true,
		Domains: []string{"replit.com"},
		Note:    "the whole IDE, not only its assistant",
	},
	{
		ID: "phind", Name: "Phind", Group: GroupCoding, Desc: "Search for developers",
		Soon:    true,
		Domains: []string{"phind.com"},
	},

	// ── answer engines ──────────────────────────────────────────────────────
	{
		ID: "perplexity", Name: "Perplexity", Group: GroupSearch, Desc: "AI answer engine",
		Soon:    true,
		Domains: []string{"perplexity.ai"},
	},
	{
		ID: "youcom", Name: "You.com", Group: GroupSearch, Desc: "AI answer engine",
		Soon:    true,
		Domains: []string{"you.com"},
	},

	// ── the consoles ────────────────────────────────────────────────────────
	{
		ID: "openrouter", Name: "OpenRouter", Group: GroupPlayground, Desc: "One API, many models",
		Soon:    true,
		Domains: []string{"openrouter.ai"},
	},
	{
		ID: "groq", Name: "Groq", Group: GroupPlayground, Desc: "Fast model inference",
		Soon:    true,
		Domains: []string{"console.groq.com"},
	},
	{
		ID: "together", Name: "Together AI", Group: GroupPlayground, Desc: "Open-model hosting",
		Soon:    true,
		Domains: []string{"api.together.xyz", "together.ai"},
	},
	{
		ID: "huggingface", Name: "Hugging Face", Group: GroupPlayground, Desc: "Model and dataset hub",
		Soon:    true,
		Domains: []string{"huggingface.co"},
		Note:    "the whole site, including model and dataset pages",
	},
}

// Groups is the order the groups are shown in, which is the order they matter
// in on a fleet.
var Groups = []Group{GroupChat, GroupCoding, GroupSearch, GroupPlayground}

// All is the catalogue.
//
// A copy, because a caller that sorted or filtered this in place would change
// what every other caller sees, and the sites list on a settings page is
// exactly the sort of thing somebody filters.
func All() []Assistant {
	out := make([]Assistant, len(all))
	copy(out, all)
	return out
}

// InGroup is one section of the list.
func InGroup(g Group) []Assistant {
	var out []Assistant
	for _, a := range all {
		if a.Group == g {
			out = append(out, a)
		}
	}
	return out
}

// Find is the entry with this id.
func Find(id string) (Assistant, bool) {
	for _, a := range all {
		if a.ID == id {
			return a, true
		}
	}
	return Assistant{}, false
}

// Default is the assistants a project watches before anybody has decided
// anything.
//
// NOT ALL OF THEM, and the line is drawn at "would somebody be surprised".
// Every general assistant is on, because that is the question this product is
// installed to answer and a fleet's first week should show real traffic rather
// than an empty page. The coding tools, the search engines and the consoles are
// off: several of them are whole sites with an assistant in them - Replit is an
// IDE, Hugging Face is a model registry - and a default that starts recording
// everything anybody does on those is a decision the product would be making on
// somebody's behalf on the day they install it.
func Default() []Assistant {
	return InGroup(GroupChat)
}

// Match finds the catalogue entry a saved rule refers to.
//
// BY DOMAIN AND NOT BY NAME, because the name is somebody's typing and the
// domains are the rule. A policy saved before this list existed says "ChatGPT"
// or "chatgpt" or "Chat GPT" and all three are the same rule; what makes it that
// rule is that it watches chatgpt.com.
//
// One shared domain is enough. A rule that watches chatgpt.com is the ChatGPT
// rule whether or not it also carries the old host, and treating it as a custom
// site because it is missing one domain would show somebody two ChatGPT rows.
func Match(domains []string) (Assistant, bool) {
	for _, d := range domains {
		host := normalise(d)
		if host == "" {
			continue
		}
		for _, a := range all {
			for _, known := range a.Domains {
				if host == known {
					return a, true
				}
			}
		}
	}
	return Assistant{}, false
}

// normalise is the same tidying the policy does to a domain somebody typed: no
// scheme, no path, no port, no leading dot, lower case.
//
// It is here rather than imported so this package depends on nothing. A
// catalogue that pulled in the policy engine could not be used by the dashboard
// without pulling that in too, and the dashboard has no business holding a
// decision engine.
func normalise(d string) string {
	s := strings.TrimSpace(strings.ToLower(d))
	if s == "" {
		return ""
	}
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndex(s, ":"); i > 0 && !strings.Contains(s[i:], "]") {
		s = s[:i]
	}
	s = strings.TrimPrefix(s, "*.")
	s = strings.Trim(s, ".")
	return s
}

// ── asking for data back ────────────────────────────────────────────────────

// Erasure is where a person writes to when something reached this assistant
// that should not have, and it is the half of this product that works
// BACKWARDS.
//
// Everything else here is about the next paste. This is about the ones before
// it: a fleet installs SolonGate on a Tuesday and the customer list went in on
// the Monday, and nothing in a browser extension can reach that. What can is a
// letter - the GDPR calls it erasure, California calls it deletion, KVKK calls
// it silme - and every one of these vendors has a route for it. Finding that
// route is twenty minutes per assistant of reading privacy pages, per person,
// per incident, and it is exactly the work a product that already knows which
// assistants a fleet uses should not make anybody do.
//
// WHAT IS IN HERE IS ONLY WHAT THE VENDOR PUBLISHED. An address this product
// invented would be a compliance page sending somebody's identity documents to
// a mailbox nobody reads, and a deadline that starts running against a request
// that never arrived. Where a vendor publishes no address, this says so and the
// screen asks for one rather than guessing.
type Erasure struct {
	// To is the published address for privacy requests, or empty where the
	// vendor publishes a form instead.
	To string
	// Portal is the vendor's own request page. It is the better route where
	// there is one - a form is tied to an account the vendor can already
	// identify, and a letter from an unknown address is a week of identity
	// checks.
	Portal string
	// How is the one thing worth knowing before writing, in a sentence.
	How string

	// Look is where this assistant keeps what it remembers, in the words its own
	// settings use.
	//
	// IT IS THE HALF THAT ANSWERS TODAY. An erasure request is answered in a
	// month; the assistant answers in a second, and what it says is what the
	// request should name. Every one of these keeps something between
	// conversations - a memory, a saved-information list, custom instructions,
	// files still attached to a project - and none of it is on any screen this
	// product can reach.
	//
	// Named rather than described, because a person has to find the menu: "Data
	// controls" and "Personalisation" are two different places in the same
	// application. Empty where this product could not verify what the setting is
	// called; the prompt works either way, which is why it is the prompt that
	// carries the instruction and this only carries the shortcut.
	Look string
}

// erasure is the directory, by assistant id. An assistant with no entry has no
// published route this product could verify; the screen says that rather than
// filling the box with a guess.
var erasure = map[string]Erasure{
	"chatgpt": {
		To:     "dsar@openai.com",
		Portal: "https://privacy.openai.com/policies",
		How: "The privacy portal is the route OpenAI answers fastest, and it ties the request to the account. " +
			"US court preservation orders have limited what OpenAI can delete from chat logs, so ask for confirmation of what was kept.",
		Look: "Settings, then Personalization, then Memory lists what it has stored and lets you delete entries one at a time. Data controls is where the history and training switches are.",
	},
	"claude": {
		To:     "privacy@anthropic.com",
		Portal: "https://privacy.claude.com",
		How: "Conversations deleted in the app go from Anthropic's systems within 30 days on their own. " +
			"Write for anything beyond that, and for a Claude for Work account write to the account owner first.",
		Look: "Settings, then Data controls for the history, and Projects for files still attached to one. Anything in a project is still there whatever the conversation says.",
	},
	"gemini": {
		Portal: "https://myactivity.google.com/product/gemini",
		How: "Deleting the activity is self-serve and is the fastest route. Conversations a human reviewer saw are kept " +
			"for up to three years whatever the activity page says, so a written request is the only way to reach those.",
		Look: "Saved info holds what you told it to remember, and Gemini Apps Activity holds the conversations. They are two separate lists and clearing one leaves the other.",
	},
	"deepseek": {
		To:   "privacy@deepseek.com",
		How:  "Deleting the account removes the content with it and cannot be undone, so export anything worth keeping first.",
		Look: "There is no memory list to open: the chat history is the whole of what it holds, and deleting the account takes it with it and cannot be undone.",
	},
	"mistral": {
		Portal: "https://api.dastra.eu/v1/client/data-subject-request/page?id=1200&key=dcObLjNDOpyYmk7rmaLHry0gvWA2OjltEUNqYT0gc1D",
		How:    "Mistral answers rights requests through one form rather than by mail. Account details are editable at admin.mistral.ai.",
		Look:   "Account settings at admin.mistral.ai for the account itself; the conversation list is the rest of it.",
	},
	"grok": {
		To:     "privacy@x.ai",
		Portal: "https://x.ai/privacy-portal",
		How:    "Put the account's own email in the subject line: xAI keys the request to it. Deletion runs within 30 days.",
		Look:   "Settings, then Data controls. The training switch is separate from the history and turning one off does not clear the other.",
	},
	"copilot": {
		Portal: "https://www.microsoft.com/en-us/privacy/privacy-support-requests",
		How: "A work tenant is different from a personal account: for Copilot for Microsoft 365 the tenant's own " +
			"administrator can find and delete it with Purview, which is faster than a request to Microsoft.",
		Look: "A work tenant keeps this where the tenant does: your own administrator can find it with Purview, which reaches further than anything in the app does.",
	},
	"metaai": {
		Portal: "https://www.facebook.com/help/contact/510058597920541",
		How: "The form covers personal information from THIRD-PARTY sources used for generative AI. " +
			"Anything posted to Facebook or Instagram is not covered by it and is deleted from those products instead.",
		Look: "Meta AI keeps what you said to it across Facebook, Instagram and WhatsApp under one account, so what it holds is not only what was said in one of them.",
	},
	"perplexity": {
		Portal: "https://www.perplexity.ai/help-center/en/articles/11564562-self-serve-data-deletion",
		How:    "Deletion is self-serve in the account settings, so there is usually nothing to write at all.",
		Look:   "Settings holds the thread history and the AI data-retention switch.",
	},
}

// ErasureFor is the published route for one assistant, and whether there is one.
func ErasureFor(id string) (Erasure, bool) {
	e, ok := erasure[strings.ToLower(strings.TrimSpace(id))]
	return e, ok
}

// ForHost is the assistant that answers on this hostname, and whether one does.
//
// SUBDOMAINS COUNT, for the reason a rule covers them: an assistant that answers
// on gemini.google.com also answers on things under it, and a caller holding a
// hostname off an audit row has whatever the browser reported rather than the
// canonical one.
//
// It is Match asked the other way round - one host against the whole list rather
// than a rule's domains against one entry - and it exists because the audit
// counts hostnames while everything a person does about an assistant is done per
// ASSISTANT: chatgpt.com and chat.openai.com are one account and one letter.
func ForHost(host string) (Assistant, bool) {
	host = normalise(host)
	if host == "" {
		return Assistant{}, false
	}
	for _, a := range all {
		for _, d := range a.Domains {
			d = normalise(d)
			if d != "" && (host == d || strings.HasSuffix(host, "."+d)) {
				return a, true
			}
		}
	}
	return Assistant{}, false
}

// ── which of the channels an assistant actually HAS ─────────────────────────

// The DLP screen draws one row per channel, and it drew every row for every
// assistant. Two of them are not acts that exist everywhere, and a row offering
// a rule about an act a site does not have is worse than a missing row:
// somebody sets it, the rule is written into the document, nothing on that
// assistant can ever match it, and the screen goes on showing a control that
// looks like it is doing something.
//
// SO THE CAPABILITY IS DECLARED HERE, BESIDE THE DOMAINS, and it is a claim
// about WHAT THE PAGE SCRIPT CAN SEE rather than about what a vendor's product
// page lists. Those are different claims and only the first one can be
// enforced.
//
// THE TWO ARE WRITTEN IN OPPOSITE DIRECTIONS, and each direction is the safe
// one for its own question.
//
// The library is a list of who HAS it, because having it is a fact about this
// script: one site's send format is parsed for it and no other site's is. An
// assistant added tomorrow cannot have it, whatever its vendor ships, until
// somebody writes the parsing - so the default has to be off or the row is a
// promise nothing keeps.
//
// The microphone is a list of who does NOT, because the hook is generic: the
// page script wraps getUserMedia on every watched site, so a call on an
// assistant nobody has tuned this for is still caught. Defaulting that one off
// would delete a working control on twenty sites to fix one.
const (
	// ChannelLibrary and ChannelVoice are shadowpolicy's channel ids, spelled
	// out here rather than imported: this package is the catalogue and sits
	// UNDER the policy engine, so an import the other way would be a cycle. The
	// pin is a test in the dashboard's views package, which imports both:
	// TestTheCatalogueSpellsTheChannelsTheEngineDoes. Without it a rename in
	// shadowpolicy would not fail to compile, it would quietly stop matching,
	// and every assistant would get every row back with nothing saying so.
	ChannelLibrary = "library"
	ChannelVoice   = "voice"
)

// hasLibrary is the assistants whose own file store this script can see.
//
// A library attachment is read out of a send's own body - the send carries
// messages[].metadata.attachments[] and each entry says where it came from - and
// that shape is ChatGPT's. Nowhere else does anything in this product see a file
// the browser never moved, so nowhere else can a rule about one fire. See
// shadowdom/inject.go, libraryFiles.
var hasLibrary = map[string]bool{
	"chatgpt": true,
}

// noVoice is the assistants with NO live call: no microphone that is opened to
// talk TO the assistant, with audio going to its servers and speech coming back.
//
// A microphone button is not a call. Gemini on the web has one and what it does
// is DICTATION - speech turned into text in the composer, which is the row above
// - so a voice row there was an operator writing a rule about something that
// cannot happen, while the act they were actually looking at was governed by a
// different row. See the same split in shadowdom/inject.go, where a microphone
// is only a call once it is wired to a peer connection.
var noVoice = map[string]bool{
	"gemini": true,
}

// HasChannel reports whether this assistant has the act a channel names.
//
// An id nobody knows has every channel except the library, which is the one
// answer each of the two lists above gives on its own terms: a site an operator
// added themselves is one this product cannot claim has a file store it can
// read, and is also one whose microphone the generic hook still catches.
func HasChannel(id, channel string) bool {
	id = normalise(id)
	switch normalise(channel) {
	case ChannelLibrary:
		return hasLibrary[id]
	case ChannelVoice:
		return !noVoice[id]
	}
	return true
}

// ChannelsMissing is what an assistant does not have, in the order Channels is
// written, for a caller that wants to SAY so rather than to filter.
func ChannelsMissing(id string) []string {
	var out []string
	for _, c := range []string{ChannelLibrary, ChannelVoice} {
		if !HasChannel(id, c) {
			out = append(out, c)
		}
	}
	return out
}
