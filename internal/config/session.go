package config

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	// SessionUnlimited is the literal that marks a session choice without an
	// absolute end ("until revoked").
	SessionUnlimited = "unlimited"
	// MinSessionChoice is the shortest accepted session choice.
	MinSessionChoice = time.Hour
	// MaxSessionChoices is the most entries oauth.session_choices may hold.
	MaxSessionChoices = 8
)

// SessionChoice is one lifetime the user may pick on the authorize form: a
// whole number of hours (at least MinSessionChoice) or Unlimited. The zero
// value is not a valid choice.
type SessionChoice struct {
	Duration  time.Duration // absolute session length; unused when Unlimited
	Unlimited bool          // no absolute end; only the idle refresh_token_ttl applies
}

// String is the canonical form of the choice, e.g. "2160h" or "unlimited". It
// is what the form's radio value, the audit record and the equality check of a
// submitted value use, so "43200m" and "720h" are the same choice.
func (c SessionChoice) String() string {
	if c.Unlimited {
		return SessionUnlimited
	}
	return fmt.Sprintf("%dh", c.Duration/time.Hour)
}

// ParseSessionChoice parses "unlimited" or a duration of at least one hour
// that is a whole number of hours.
func ParseSessionChoice(s string) (SessionChoice, error) {
	s = strings.TrimSpace(s)
	if s == SessionUnlimited {
		return SessionChoice{Unlimited: true}, nil
	}
	d, err := time.ParseDuration(s)
	switch {
	case err != nil:
		return SessionChoice{}, fmt.Errorf("%q is neither a duration (Go syntax, e.g. 720h; there is no d unit) nor %q", s, SessionUnlimited)
	case d < MinSessionChoice:
		return SessionChoice{}, fmt.Errorf("%q is shorter than the minimum of %s", s, MinSessionChoice)
	case d%time.Hour != 0:
		return SessionChoice{}, fmt.Errorf("%q must be a whole number of hours", s)
	}
	return SessionChoice{Duration: d}, nil
}

// resolveSessions parses SessionChoices and SessionDefault into Sessions and
// DefaultSession. Both stay empty when no choices are configured (a fixed
// max_session_ttl then applies) and when there are errors.
func (o *OAuth) resolveSessions() []error {
	o.Sessions, o.DefaultSession = nil, SessionChoice{}
	def := strings.TrimSpace(o.SessionDefault)
	if len(o.SessionChoices) == 0 {
		if def != "" {
			return []error{errors.New("oauth.session_default: requires oauth.session_choices")}
		}
		return nil
	}

	var errs []error
	if len(o.SessionChoices) > MaxSessionChoices {
		errs = append(errs, fmt.Errorf("oauth.session_choices: %d entries, at most %d are allowed", len(o.SessionChoices), MaxSessionChoices))
	}
	choices := make([]SessionChoice, 0, len(o.SessionChoices))
	seen := map[string]int{}
	for i, raw := range o.SessionChoices {
		c, err := ParseSessionChoice(raw)
		if err != nil {
			errs = append(errs, fmt.Errorf("oauth.session_choices[%d]: %v", i, err))
			continue
		}
		if j, dup := seen[c.String()]; dup {
			errs = append(errs, fmt.Errorf("oauth.session_choices[%d]: duplicates [%d] (%s)", i, j, c))
			continue
		}
		seen[c.String()] = i
		choices = append(choices, c)
	}

	chosen := SessionChoice{}
	if def == "" {
		if len(choices) > 0 {
			chosen = choices[0]
		}
	} else if c, err := ParseSessionChoice(def); err != nil {
		errs = append(errs, fmt.Errorf("oauth.session_default: %v", err))
	} else if _, ok := seen[c.String()]; !ok {
		errs = append(errs, fmt.Errorf("oauth.session_default: %s is not one of oauth.session_choices", c))
	} else {
		chosen = c
	}
	if len(errs) > 0 {
		return errs
	}
	o.Sessions, o.DefaultSession = choices, chosen
	return nil
}
