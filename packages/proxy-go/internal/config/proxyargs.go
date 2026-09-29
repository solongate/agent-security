package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/codeyevsky/solongate/proxy/internal/core"
)

// Flag parsing and configuration for the MCP PROXY runtime — the mode where the
// binary sits between an MCP client and an upstream server.
//
// It lives beside the CLI's own configuration because the two share the API-key
// resolution and the licence gate, and those had drifted before: a key accepted
// by one path and refused by the other reads to the user as "it works from the
// terminal but not from my editor".

// UpstreamConfig is the server being protected. Two modes: spawn a child
// process (stdio), or connect to a URL (sse/http).
type UpstreamConfig struct {
	Transport string            `json:"transport,omitempty"`
	Command   string            `json:"command"`
	Args      []string          `json:"args,omitempty"`
	Env       map[string]string `json:"env,omitempty"`
	Cwd       string            `json:"cwd,omitempty"`
	URL       string            `json:"url,omitempty"`
}

type ProxyConfig struct {
	Upstream         UpstreamConfig
	Policy           core.PolicySet
	Name             string
	Verbose          bool
	RateLimitPerTool int
	GlobalRateLimit  int
	APIKey           string
	APIURL           string
	Port             int
	// PolicyPath is the resolved absolute path of the policy file, empty when
	// the policy is cloud-only.
	PolicyPath string
	PolicyID   string
	AgentName  string
}

// These carry the same wording as the Node implementation. They are matched on
// by nothing, but a user who searches the message should land on the same answer
// whichever binary printed it.
var (
	ErrNoUpstream = errors.New("No upstream server command provided.\n\n" +
		"If you just want to get started, run:\n" +
		"  solongate\n")
	ErrBadKeyFormat = errors.New("This machine's stored credential is not valid.\n\n" +
		"Pair it again:\n\n" +
		"  solongate\n\n" +
		"  then add your account from the Accounts panel.\n")
	ErrProxyNotAuthenticated = errors.New("Not logged in. Run this once to get started:\n\n" +
		"  solongate\n\n" +
		"  then add your account from the Accounts panel.\n")
)

// defaultPolicy is what applies until a cloud policy arrives: allow everything.
// DENY rules added from the dashboard are what restrict it. A default-DENY here
// would mean every machine is dead in the water for the seconds between install
// and first sync.
func defaultPolicy() core.PolicySet {
	return core.PolicySet{
		ID:          "default",
		Name:        "Default (Allow All)",
		Description: "Allows all tools by default. Add DENY rules from the dashboard to restrict.",
		Version:     1,
		Rules: []core.PolicyRule{{
			ID:                "_default-allow-all",
			Description:       "Allow all tools by default",
			Effect:            core.EffectAllow,
			Priority:          9999,
			ToolPattern:       "*",
			MinimumTrustLevel: core.TrustUntrusted,
			Enabled:           true,
		}},
	}
}

// ensureCatchAllAllow appends a catch-all ALLOW at the lowest priority when the
// policy has none.
//
// Without it, anything that matches no DENY rule falls through to default-deny
// and the proxy blocks everything, including the operations the user never
// meant to govern. The catch-all at 9999 lets the un-denied through while
// keeping every explicit rule ahead of it.
func ensureCatchAllAllow(p core.PolicySet, now string) core.PolicySet {
	for _, r := range p.Rules {
		if r.Effect == core.EffectAllow && r.ToolPattern == "*" && r.Enabled {
			return p
		}
	}
	p.Rules = append(p.Rules, core.PolicyRule{
		ID:                "_solongate-catch-all-allow",
		Description:       "Auto-added: allow everything not explicitly denied",
		Effect:            core.EffectAllow,
		Priority:          9999,
		ToolPattern:       "*",
		MinimumTrustLevel: core.TrustUntrusted,
		Enabled:           true,
		CreatedAt:         now,
		UpdatedAt:         now,
	})
	return p
}

// LoadPolicyFile reads a policy from a path. A path that is not there is not an
// error: it means the policy comes from the cloud, and the default stands in
// until it does.
func LoadPolicyFile(source string, now string) core.PolicySet {
	abs, err := filepath.Abs(source)
	if err != nil {
		return defaultPolicy()
	}
	b, err := os.ReadFile(abs)
	if err != nil {
		return defaultPolicy()
	}
	var p core.PolicySet
	if json.Unmarshal(b, &p) != nil {
		return defaultPolicy()
	}
	return ensureCatchAllAllow(p, now)
}

func resolvePolicyPath(source string) string {
	abs, err := filepath.Abs(source)
	if err != nil {
		return ""
	}
	if _, err := os.Stat(abs); err != nil {
		return ""
	}
	return abs
}

// A ${VAR} that was never expanded. MCP clients put `"SOLONGATE_API_KEY":
// "${SOLONGATE_API_KEY}"` in .mcp.json and some of them pass it through
// literally; treating that string as a key gets a 401 that reads like a revoked
// account rather than like a config error.
var unexpandedRef = regexp.MustCompile(`^\$\{.+\}$`)

// The proxy's own .env reader. Narrower than the CLI's on purpose: it only
// accepts a value that already looks like a key, so a placeholder line in a
// checked-in .env cannot become this machine's credential.
var dotenvKeyLine = regexp.MustCompile(`(?m)^SOLONGATE_API_KEY=(sg_(?:live|test)_\w+)`)

func proxyDotenvKey() string {
	abs, err := filepath.Abs(".env")
	if err != nil {
		return ""
	}
	b, err := os.ReadFile(abs)
	if err != nil {
		return ""
	}
	if m := dotenvKeyLine.FindSubmatch(b); m != nil {
		return string(m[1])
	}
	return ""
}

type proxyFileConfig struct {
	Upstream         *UpstreamConfig `json:"upstream"`
	Policy           string          `json:"policy"`
	Name             string          `json:"name"`
	Verbose          *bool           `json:"verbose"`
	RateLimitPerTool *int            `json:"rateLimitPerTool"`
	GlobalRateLimit  *int            `json:"globalRateLimit"`
	Port             *int            `json:"port"`
	APIKey           string          `json:"apiKey"`
	APIURL           string          `json:"apiUrl"`
	PolicyID         string          `json:"policyId"`
}

// ParseProxyArgs turns the arguments after the program name into a ProxyConfig.
//
//	solongate-proxy [options] -- <command> [args...]
//
// The `--` may be eaten by npx, so the first token that is not a flag is also
// treated as the start of the upstream command. That is not defensive coding
// for its own sake: without it, `npx @solongate/proxy --policy p.json node
// server.js` starts a proxy with no upstream and fails with a message about a
// missing command the user did type.
func ParseProxyArgs(args []string, now string) (ProxyConfig, error) {
	var (
		policySource      string
		name              = "solongate-proxy"
		verbose           bool
		rateLimitPerTool  int
		globalRateLimit   int
		configFile        string
		apiKey            string
		apiURL            string
		upstreamURL       string
		upstreamTransport string
		port              int
		policyID          string
		agentName         string
		upstreamArgs      []string
	)

	flags := args
	for i, a := range args {
		if a == "--" {
			flags = args[:i]
			upstreamArgs = append([]string{}, args[i+1:]...)
			break
		}
	}

	next := func(i *int) string {
		*i++
		if *i < len(flags) {
			return flags[*i]
		}
		return ""
	}

	for i := 0; i < len(flags); i++ {
		if !strings.HasPrefix(flags[i], "--") {
			if len(upstreamArgs) == 0 {
				upstreamArgs = append(upstreamArgs, flags[i:]...)
			}
			break
		}
		switch flags[i] {
		case "--policy":
			policySource = next(&i)
		case "--name":
			name = next(&i)
		case "--verbose":
			verbose = true
		case "--rate-limit":
			rateLimitPerTool, _ = strconv.Atoi(next(&i))
		case "--global-rate-limit":
			globalRateLimit, _ = strconv.Atoi(next(&i))
		case "--config":
			configFile = next(&i)
		case "--api-key":
			apiKey = next(&i)
		case "--api-url":
			apiURL = next(&i)
		case "--upstream-url":
			upstreamURL = next(&i)
		case "--upstream-transport":
			upstreamTransport = next(&i)
		case "--port":
			port, _ = strconv.Atoi(next(&i))
		case "--policy-id", "--id":
			policyID = next(&i)
		case "--agent-name":
			agentName = next(&i)
		}
	}

	// The licence gate, before any return path so no branch can skip it.
	if unexpandedRef.MatchString(apiKey) {
		apiKey = ""
	}
	if apiKey == "" {
		apiKey = proxyDotenvKey()
	}
	if apiKey == "" {
		if env := os.Getenv("SOLONGATE_API_KEY"); env != "" && !unexpandedRef.MatchString(env) {
			apiKey = env
		}
	}
	if apiKey == "" {
		// The zero-config path: log in once from the dataroom and every
		// invocation works with no key anywhere.
		apiKey = LoadCredentialFile().APIKey
	}
	// NO CREDENTIAL IS NOT AN ERROR. This used to refuse the whole config, so the
	// proxy could not come up at all on a machine with no service — and that is
	// the ordinary way this runs. With no key nothing cloud-side happens and the
	// policy is the file on this machine, the same one the guard reads.
	//
	// A MALFORMED key counts as none for the same reason: it cannot be used, and
	// refusing to start over it leaves the agent with no gate rather than a local
	// one.
	if !strings.HasPrefix(apiKey, "sg_live_") && !strings.HasPrefix(apiKey, "sg_test_") {
		apiKey = ""
	}

	// With no --policy, THIS MACHINE'S FILE — so the proxy and the hook decide
	// from the same rules. A policy.json in the working directory still wins when
	// it is there, which is how a project pins its own.
	if policySource == "" {
		own := filepath.Join(Dir(), policyFileName)
		if _, err := os.Stat(policyFileName); err == nil {
			policySource = policyFileName
		} else if _, err := os.Stat(own); err == nil {
			policySource = own
		}
	}

	resolvedPolicyPath := ""
	if policySource != "" {
		resolvedPolicyPath = resolvePolicyPath(policySource)
	}

	if configFile != "" {
		abs, err := filepath.Abs(configFile)
		if err != nil {
			return ProxyConfig{}, err
		}
		b, err := os.ReadFile(abs)
		if err != nil {
			return ProxyConfig{}, err
		}
		var fc proxyFileConfig
		if err := json.Unmarshal(b, &fc); err != nil {
			return ProxyConfig{}, err
		}
		if fc.Upstream == nil {
			return ProxyConfig{}, errors.New(`Config file must include "upstream" with at least "command" or "url"`)
		}
		cfgPolicySource := firstNonEmpty(fc.Policy, policySource, "policy.json")
		cfg := ProxyConfig{
			Upstream:         *fc.Upstream,
			Policy:           LoadPolicyFile(cfgPolicySource, now),
			Name:             firstNonEmpty(fc.Name, name),
			Verbose:          verbose,
			RateLimitPerTool: rateLimitPerTool,
			GlobalRateLimit:  globalRateLimit,
			APIKey:           apiKey,
			APIURL:           firstNonEmpty(apiURL, fc.APIURL),
			Port:             port,
			PolicyPath:       resolvePolicyPath(cfgPolicySource),
			PolicyID:         firstNonEmpty(policyID, fc.PolicyID),
			AgentName:        agentName,
		}
		if fc.Verbose != nil {
			cfg.Verbose = *fc.Verbose
		}
		if fc.RateLimitPerTool != nil && rateLimitPerTool == 0 {
			cfg.RateLimitPerTool = *fc.RateLimitPerTool
		}
		if fc.GlobalRateLimit != nil && globalRateLimit == 0 {
			cfg.GlobalRateLimit = *fc.GlobalRateLimit
		}
		if fc.Port != nil && port == 0 {
			cfg.Port = *fc.Port
		}
		return cfg, nil
	}

	if upstreamURL != "" {
		transport := upstreamTransport
		if transport == "" {
			// /sse in the path is how every SSE endpoint in the wild is
			// spelled; anything else is StreamableHTTP.
			if strings.Contains(upstreamURL, "/sse") {
				transport = "sse"
			} else {
				transport = "http"
			}
		}
		return ProxyConfig{
			Upstream:         UpstreamConfig{Transport: transport, URL: upstreamURL},
			Policy:           LoadPolicyFile(firstNonEmpty(policySource, "policy.json"), now),
			Name:             name,
			Verbose:          verbose,
			RateLimitPerTool: rateLimitPerTool,
			GlobalRateLimit:  globalRateLimit,
			APIKey:           apiKey,
			APIURL:           apiURL,
			Port:             port,
			PolicyPath:       resolvedPolicyPath,
			PolicyID:         policyID,
			AgentName:        agentName,
		}, nil
	}

	if len(upstreamArgs) == 0 {
		return ProxyConfig{}, ErrNoUpstream
	}

	transport := upstreamTransport
	if transport == "" {
		transport = "stdio"
	}
	return ProxyConfig{
		Upstream: UpstreamConfig{
			Transport: transport,
			Command:   upstreamArgs[0],
			Args:      upstreamArgs[1:],
			// A deliberately minimal environment: the upstream gets what it
			// needs to find binaries and a home directory, and nothing else
			// this process happens to be carrying.
			Env: map[string]string{
				"PATH":        os.Getenv("PATH"),
				"HOME":        os.Getenv("HOME"),
				"USERPROFILE": os.Getenv("USERPROFILE"),
			},
		},
		Policy:           LoadPolicyFile(firstNonEmpty(policySource, "policy.json"), now),
		Name:             name,
		Verbose:          verbose,
		RateLimitPerTool: rateLimitPerTool,
		GlobalRateLimit:  globalRateLimit,
		APIKey:           apiKey,
		APIURL:           apiURL,
		Port:             port,
		PolicyPath:       resolvedPolicyPath,
		PolicyID:         policyID,
		AgentName:        agentName,
	}, nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
