package old_code

//// AccessType defines the type of access control.
//type AccessType int
//
//const (
//	NoAccess AccessType = iota
//	PermitAll
//	RoleRequired
//	DenyAll
//)
//
//// AbstractRequestMatcherRegistry defines a structure for request matchers.
//type AbstractRequestMatcherRegistry struct {
//	Pattern string
//}
//
//// AuthorizationManagerRequestMatcherRegistry defines access control for matched requests.
//type AuthorizationManagerRequestMatcherRegistry struct {
//	Matcher      *AbstractRequestMatcherRegistry
//	Access       AccessType
//	RequiredRole string
//	Config       *SecurityConfig
//}
//
//// SecurityConfig holds the security configurations.
//type SecurityConfig struct {
//	matchers map[string]*AuthorizationManagerRequestMatcherRegistry
//}
//
//// NewSecurityConfig creates a new instance of SecurityConfig.
//func NewSecurityConfig() *SecurityConfig {
//	return &SecurityConfig{
//		matchers: make(map[string]*AuthorizationManagerRequestMatcherRegistry),
//	}
//}
//
//// RequestMatchers creates a new AbstractRequestMatcherRegistry.
//func (sc *SecurityConfig) RequestMatchers(pattern string) *AuthorizationManagerRequestMatcherRegistry {
//	if ac, exists := sc.matchers[pattern]; exists {
//		// If a matcher already exists for this pattern, return it for modification
//		return ac
//	}
//
//	rm := &AbstractRequestMatcherRegistry{Pattern: pattern}
//	ac := &AuthorizationManagerRequestMatcherRegistry{Matcher: rm, Access: NoAccess, Config: sc}
//	sc.matchers[pattern] = ac
//	return ac
//}
//
//// permitAll allows access to the path.
//func (ac *AuthorizationManagerRequestMatcherRegistry) permitAll() *SecurityConfig {
//	ac.Access = PermitAll
//	return ac.Config
//}
//
//// hasRole restricts access to users with the specified role.
//func (ac *AuthorizationManagerRequestMatcherRegistry) hasRole(role string) *SecurityConfig {
//	ac.Access = RoleRequired
//	ac.RequiredRole = role
//	return ac.Config
//}
//
//// denyAll restricts access to the path for all users.
//func (ac *AuthorizationManagerRequestMatcherRegistry) denyAll() *SecurityConfig {
//	ac.Access = DenyAll
//	return ac.Config
//}
//
//// ***************************************************************************** //
//
//// GrantedAuthority represents an authority granted to the user.
//type GrantedAuthority interface {
//	GetAuthority() string
//}
//
//// UserDetails defines the user details interface.
//type UserDetails interface {
//	GetAuthorities() []GrantedAuthority
//	GetPassword() string
//	GetUsername() string
//	IsAccountNonExpired() bool
//	IsAccountNonLocked() bool
//	IsCredentialsNonExpired() bool
//	IsEnabled() bool
//}
//
//// User implements the UserDetails interface.
//type User struct {
//	Username              string
//	Password              string
//	Authorities           []GrantedAuthority
//	AccountNonExpired     bool
//	AccountNonLocked      bool
//	CredentialsNonExpired bool
//	Enabled               bool
//}
//
//// GetAuthorities returns the authorities granted to the user.
//func (u *User) GetAuthorities() []GrantedAuthority {
//	return u.Authorities
//}
//
//// GetPassword returns the password used to authenticate the user.
//func (u *User) GetPassword() string {
//	return u.Password
//}
//
//// GetUsername returns the username used to authenticate the user.
//func (u *User) GetUsername() string {
//	return u.Username
//}
//
//// IsAccountNonExpired indicates whether the user's account has expired.
//func (u *User) IsAccountNonExpired() bool {
//	return u.AccountNonExpired
//}
//
//// IsAccountNonLocked indicates whether the user is locked or unlocked.
//func (u *User) IsAccountNonLocked() bool {
//	return u.AccountNonLocked
//}
//
//// IsCredentialsNonExpired indicates whether the user's credentials have expired.
//func (u *User) IsCredentialsNonExpired() bool {
//	return u.CredentialsNonExpired
//}
//
//// IsEnabled indicates whether the user is enabled or disabled.
//func (u *User) IsEnabled() bool {
//	return u.Enabled
//}
//
//// SimpleGrantedAuthority Example implementation of GrantedAuthority
//type SimpleGrantedAuthority struct {
//	authority string
//}
//
//func (ga *SimpleGrantedAuthority) GetAuthority() string {
//	return ga.authority
//}
//
//// UserDetailsService interface defines the contract for loading user details.
//type UserDetailsService interface {
//	// LoadUserByUsername locates the user based on the username.
//	LoadUserByUsername(username string) (UserDetails, error)
//}
//
//// ***************************************************************************** //
//
//// Authentication represents the token for an authentication request or for an authenticated principal.
//type Authentication interface {
//	GetAuthorities() []GrantedAuthority    // Get authorities granted to the principal
//	GetCredentials() interface{}           // Get credentials (usually a password)
//	GetDetails() interface{}               // Get additional details about the authentication request
//	GetPrincipal() interface{}             // Get the principal being authenticated
//	IsAuthenticated() bool                 // Check if the authentication is successful
//	SetAuthenticated(isAuthenticated bool) // Set the authentication status
//}
//
//// UsernamePasswordAuthenticationToken represents an authentication token for username and password.
//type UsernamePasswordAuthenticationToken struct {
//	Principal     string             // The user’s identity (username)
//	Credentials   string             // The credentials (password)
//	Authorities   []GrantedAuthority // The granted authorities
//	Authenticated bool               // Indicates if the token is authenticated
//	Details       interface{}        // Additional details about the authentication request
//}
//
//func (token *UsernamePasswordAuthenticationToken) GetAuthorities() []GrantedAuthority {
//	return token.Authorities
//}
//
//func (token *UsernamePasswordAuthenticationToken) GetDetails() interface{} {
//	return token.Details
//}
//
//// NewUsernamePasswordAuthenticationToken creates an unauthenticated token.
//func NewUsernamePasswordAuthenticationToken(principal, credentials string) *UsernamePasswordAuthenticationToken {
//	return &UsernamePasswordAuthenticationToken{
//		Principal:     principal,
//		Credentials:   credentials,
//		Authenticated: false,
//	}
//}
//
//// NewAuthenticatedToken creates an authenticated token with authorities.
//func NewAuthenticatedToken(principal, credentials string, authorities []GrantedAuthority) *UsernamePasswordAuthenticationToken {
//	return &UsernamePasswordAuthenticationToken{
//		Principal:     principal,
//		Credentials:   credentials,
//		Authorities:   authorities,
//		Authenticated: true,
//	}
//}
//
//// GetCredentials returns the credentials.
//func (token *UsernamePasswordAuthenticationToken) GetCredentials() interface{} {
//	return token.Credentials
//}
//
//// GetPrincipal returns the principal.
//func (token *UsernamePasswordAuthenticationToken) GetPrincipal() interface{} {
//	return token.Principal
//}
//
//// IsAuthenticated checks if the token is authenticated.
//func (token *UsernamePasswordAuthenticationToken) IsAuthenticated() bool {
//	return token.Authenticated
//}
//
//// SetAuthenticated sets the authenticated status.
//func (token *UsernamePasswordAuthenticationToken) SetAuthenticated(isAuthenticated bool) {
//	token.Authenticated = isAuthenticated
//}
//
//// EraseCredentials clears the credentials.
//func (token *UsernamePasswordAuthenticationToken) EraseCredentials() {
//	token.Credentials = ""
//}
//
//// AuthenticationException is the base type for authentication-related errors.
//type AuthenticationException struct {
//	Message string
//}
//
//func (e *AuthenticationException) Error() string {
//	return e.Message
//}
//
//// DisabledException is thrown when an account is disabled.
//type DisabledException struct {
//	Message string
//}
//
//func (e *DisabledException) Error() string {
//	return e.Message
//}
//
//// LockedException is thrown when an account is locked.
//type LockedException struct {
//	Message string
//}
//
//func (e *LockedException) Error() string {
//	return e.Message
//}
//
//// BadCredentialsException is thrown when credentials are incorrect.
//type BadCredentialsException struct {
//	Message string
//}
//
//func (e *BadCredentialsException) Error() string {
//	return e.Message
//}
//
//// AuthenticationManager defines the interface for authentication management.
//type AuthenticationManager interface {
//	// authenticate attempts to authenticate the passed Authentication object,
//	// returning a fully populated Authentication object (including granted authorities) if successful.
//	authenticate(Auth Authentication) (Authentication, error)
//}
