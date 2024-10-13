package FromJava

type CompromisedPasswordChecker interface {
	Check(password string) CompromisedPasswordDecision
}
