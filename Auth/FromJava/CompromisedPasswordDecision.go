package FromJava

type CompromisedPasswordDecision struct {
	compromised bool
}

// NewCompromisedPasswordDecision creates a New instance of CompromisedPasswordDecision.
func NewCompromisedPasswordDecision(compromised bool) *CompromisedPasswordDecision {
	return &CompromisedPasswordDecision{
		compromised: compromised,
	}
}

// IsCompromised checks if the password is compromised.
func (c *CompromisedPasswordDecision) IsCompromised() bool {
	return c.compromised
}
