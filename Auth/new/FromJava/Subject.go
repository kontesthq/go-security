package FromJava

// Subject represents a subject that contains principals.
type Subject interface {
	GetPrincipals() []Principal // Returns the principals associated with the subject.
}
