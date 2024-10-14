package FromJava

// Subject represents a subject that contains principals.
type Subject interface {
	GetPrincipals() []string // Returns the principals associated with the subject.
}
