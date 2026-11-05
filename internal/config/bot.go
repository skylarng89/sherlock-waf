package config

import (
	"path"
	"slices"
	"strconv"
	"strings"
	"time"
)

// BotPolicy configures the bot module: challenge pages for suspicious clients.
// Every field is optional and inherits like the rest of a policy.
type BotPolicy struct {
	Enabled *bool `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	// Challenge is pow (self-hosted proof of work), turnstile or hcaptcha. The
	// provider secrets come from the environment (SHERLOCK_TURNSTILE_SECRET,
	// SHERLOCK_HCAPTCHA_SECRET), never from the configuration.
	Challenge string `yaml:"challenge,omitempty" json:"challenge,omitempty"`
	// Difficulty is the number of leading zero hex digits the proof of work needs
	// (4 takes a browser well under a second).
	Difficulty int `yaml:"difficulty,omitempty" json:"difficulty,omitempty"`
	// ClearanceTTL is how long a passed challenge is remembered.
	ClearanceTTL Duration `yaml:"clearance_ttl,omitempty" json:"clearance_ttl,omitempty"`
	// SiteKey is the public key of a turnstile or hcaptcha widget.
	SiteKey string `yaml:"site_key,omitempty" json:"site_key,omitempty"`
	// VerifiedBots says what to do with clients that claim to be a search
	// engine and whose address checks out by reverse DNS: allow (default),
	// challenge or block. Claims that do not verify are treated as ordinary clients.
	VerifiedBots string    `yaml:"verified_bots,omitempty" json:"verified_bots,omitempty"`
	Rules        []BotRule `yaml:"rules,omitempty" json:"rules,omitempty"`
}

// BotRule challenges (or blocks, or lets through) requests that match.
type BotRule struct {
	Match  BotMatch `yaml:"match,omitempty" json:"match"`
	Action string   `yaml:"action,omitempty" json:"action,omitempty"` // challenge (default) | block | allow
}

// BotMatch selects requests; every set field must match.
type BotMatch struct {
	Paths     []string `yaml:"paths,omitempty" json:"paths,omitempty"`
	Methods   []string `yaml:"methods,omitempty" json:"methods,omitempty"`
	Countries []string `yaml:"countries,omitempty" json:"countries,omitempty"`
	// Reputation true matches clients on a reputation list.
	Reputation *bool `yaml:"reputation,omitempty" json:"reputation,omitempty"`
}

// Bot challenge types and rule actions.
const (
	ChallengePoW       = "pow"
	ChallengeTurnstile = "turnstile"
	ChallengeHCaptcha  = "hcaptcha"
	BotActionAllow     = "allow"

	DefaultBotDifficulty = 4
	DefaultBotTTL        = 30 * time.Minute
)

// EffectiveBot is the resolved bot policy.
type EffectiveBot struct {
	Enabled      bool          `json:"enabled"`
	Challenge    string        `json:"challenge"`
	Difficulty   int           `json:"difficulty"`
	ClearanceTTL time.Duration `json:"clearance_ttl"`
	SiteKey      string        `json:"site_key,omitempty"`
	VerifiedBots string        `json:"verified_bots"`
	Rules        []BotRule     `json:"rules"`
}

func newEffectiveBot() EffectiveBot {
	return EffectiveBot{Challenge: ChallengePoW, Difficulty: DefaultBotDifficulty, ClearanceTTL: DefaultBotTTL, VerifiedBots: BotActionAllow, Rules: []BotRule{}}
}

func (e *EffectivePolicy) applyBot(p *Policy, src string) {
	b := p.Bot
	if b == nil {
		return
	}
	set := func(f string) { e.Sources["bot."+f] = src }
	e.Bot.Enabled = b.Enabled == nil || *b.Enabled
	set("enabled")
	if b.Challenge != "" {
		e.Bot.Challenge = b.Challenge
		set("challenge")
	}
	if b.Difficulty != 0 {
		e.Bot.Difficulty = b.Difficulty
		set("difficulty")
	}
	if b.ClearanceTTL != 0 {
		e.Bot.ClearanceTTL = b.ClearanceTTL.Std()
		set("clearance_ttl")
	}
	if b.SiteKey != "" {
		e.Bot.SiteKey = b.SiteKey
		set("site_key")
	}
	if b.VerifiedBots != "" {
		e.Bot.VerifiedBots = b.VerifiedBots
		set("verified_bots")
	}
	if b.Rules != nil {
		e.Bot.Rules = slices.Clone(b.Rules)
		set("rules")
	}
}

func (p *Policy) applyBotDefaults() {
	if p.Bot == nil {
		return
	}
	for i := range p.Bot.Rules {
		if p.Bot.Rules[i].Action == "" {
			p.Bot.Rules[i].Action = ActionChallenge
		}
	}
}

func (p *Policy) validateBot(pth string, errs *Errors) {
	b := p.Bot
	if b == nil {
		return
	}
	if !slices.Contains([]string{"", ChallengePoW, ChallengeTurnstile, ChallengeHCaptcha}, b.Challenge) {
		errs.add(pth+"/challenge", CodeInvalid, "must be pow, turnstile or hcaptcha")
	}
	if b.Difficulty != 0 && (b.Difficulty < 1 || b.Difficulty > 6) {
		errs.add(pth+"/difficulty", CodeOutOfRange, "must be between 1 and 6 hex digits")
	}
	if t := b.ClearanceTTL.Std(); t != 0 && (t < time.Minute || t > 7*24*time.Hour) {
		errs.add(pth+"/clearance_ttl", CodeOutOfRange, "must be between 1m and 7d")
	}
	if !slices.Contains([]string{"", BotActionAllow, ActionChallenge, ActionBlock}, b.VerifiedBots) {
		errs.add(pth+"/verified_bots", CodeInvalid, "must be allow, challenge or block")
	}
	if len(b.SiteKey) > 200 || strings.ContainsAny(b.SiteKey, "\"'<>& \r\n") {
		errs.add(pth+"/site_key", CodeInvalid, "must be the public site key without spaces or quotes")
	}
	if len(b.Rules) > 50 {
		errs.add(pth+"/rules", CodeOutOfRange, "at most 50 rules")
	}
	for i, r := range b.Rules {
		rp := pth + "/rules/" + strconv.Itoa(i)
		if !slices.Contains([]string{"", ActionChallenge, ActionBlock, BotActionAllow}, r.Action) {
			errs.add(rp+"/action", CodeInvalid, "must be challenge, block or allow")
		}
		for j, pat := range r.Match.Paths {
			if !strings.HasPrefix(pat, "/") {
				errs.add(rp+"/match/paths/"+strconv.Itoa(j), CodeInvalid, "must start with '/'")
			} else if _, err := path.Match(pat, "/"); err != nil {
				errs.add(rp+"/match/paths/"+strconv.Itoa(j), CodeInvalid, "invalid glob: %v", err)
			}
		}
		for j, m := range r.Match.Methods {
			if !slices.Contains(validVerbs, m) {
				errs.add(rp+"/match/methods/"+strconv.Itoa(j), CodeInvalid, "%q is not an HTTP method", m)
			}
		}
		for j, c := range r.Match.Countries {
			if !countryRE.MatchString(c) {
				errs.add(rp+"/match/countries/"+strconv.Itoa(j), CodeInvalid, "%q is not an ISO 3166-1 alpha-2 code in capitals", c)
			}
		}
	}
}
