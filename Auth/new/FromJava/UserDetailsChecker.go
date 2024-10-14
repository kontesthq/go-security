package FromJava

type UserDetailsChecker interface {
	Check(toCheck UserDetails) *AuthenticationException
}
