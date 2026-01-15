# Spring Security Deep Dive

This document provides an in-depth explanation of how Spring Security works in this CSRF protection demo application.

## Spring Security Architecture Overview

Spring Security is built on a **filter chain** architecture. Every HTTP request passes through a series of filters before reaching your controller. Each filter has a specific security responsibility.

## 1. @EnableWebSecurity - The Bootstrap

```java
@EnableWebSecurity
```

This annotation does several critical things:

- **Imports** `WebSecurityConfiguration` which creates the Spring Security filter chain
- **Registers** the `springSecurityFilterChain` bean (a `DelegatingFilterProxy`)
- **Activates** Spring Security's web security support
- **Creates** the infrastructure for `SecurityFilterChain` beans

When your application starts, Spring Security registers itself as a **servlet filter** in your web application's filter chain with the name `springSecurityFilterChain`.

## 2. SecurityFilterChain - The Core Configuration

```java
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception
```

This method returns a `SecurityFilterChain` bean that defines which filters should be applied and in what order. The `HttpSecurity` object is a **builder** that constructs the filter chain.

### Internal Filter Chain (in order):

1. **SecurityContextPersistenceFilter** - Loads/stores security context from session
2. **LogoutFilter** - Handles logout requests
3. **UsernamePasswordAuthenticationFilter** - Processes login form submissions
4. **DefaultLoginPageGeneratingFilter** - Generates default login page (overridden by your custom page)
5. **BasicAuthenticationFilter** - Handles HTTP Basic authentication
6. **RequestCacheAwareFilter** - Restores saved requests after authentication
7. **SecurityContextHolderAwareRequestFilter** - Wraps request with security methods
8. **AnonymousAuthenticationFilter** - Creates anonymous authentication if no user logged in
9. **SessionManagementFilter** - Manages session fixation protection
10. **ExceptionTranslationFilter** - Translates security exceptions to HTTP responses
11. **FilterSecurityInterceptor** - Makes the final authorization decision

## 3. Authorization Configuration

```java
.authorizeHttpRequests(authz -> authz
    .requestMatchers("/login", "/css/**").permitAll()
    .anyRequest().authenticated()
)
```

### How it works:

**At startup:**
- Spring Security builds a `RequestMatcherDelegatingAuthorizationManager`
- Each rule is registered as a `RequestMatcherEntry` with an authorization decision

**On each request:**
1. Request enters `FilterSecurityInterceptor` (or `AuthorizationFilter` in newer versions)
2. Request URL is matched against patterns in order
3. First matching rule determines the authorization requirement
4. If `permitAll()` → access granted immediately
5. If `authenticated()` → checks if `SecurityContext` has an authenticated user

**Authorization Decision Process:**
```
Request → RequestMatcher.matches() → AuthorizationManager.check()
    ↓
If authenticated required and user not logged in:
    ↓
AccessDeniedException → ExceptionTranslationFilter
    ↓
Redirects to /login (because of form login configuration)
```

## 4. Form Login Configuration

```java
.formLogin(form -> form
    .loginPage("/login")
    .defaultSuccessUrl("/dashboard", true)
    .permitAll()
)
```

### What happens internally:

**Filter Added:** `UsernamePasswordAuthenticationFilter`

**Login Process Flow:**

1. **User visits protected page** (e.g., /dashboard)
   - Not authenticated → redirected to `/login`
   - Original URL saved in `RequestCache`

2. **User submits login form** to `/login` (POST)
   - `UsernamePasswordAuthenticationFilter` intercepts
   - Extracts `username` and `password` from request parameters
   - Creates `UsernamePasswordAuthenticationToken` (unauthenticated)

3. **Authentication Process:**
   ```
   UsernamePasswordAuthenticationFilter
       ↓
   AuthenticationManager (ProviderManager)
       ↓
   DaoAuthenticationProvider
       ↓ calls loadUserByUsername()
   UserDetailsService (your InMemoryUserDetailsManager)
       ↓ returns UserDetails
   Back to DaoAuthenticationProvider
       ↓ compares passwords using PasswordEncoder
   If passwords match:
       ↓ creates authenticated UsernamePasswordAuthenticationToken
   Returns to filter
       ↓
   Stores authentication in SecurityContext
       ↓
   SecurityContextPersistenceFilter saves to HTTP session
       ↓
   Redirects to /dashboard
   ```

4. **Session Storage:**
   - `SecurityContext` (containing authentication) stored in `HttpSession`
   - Session cookie (`JSESSIONID`) sent to browser
   - On subsequent requests, `SecurityContextPersistenceFilter` loads the `SecurityContext` from session

## 5. UserDetailsService - User Loading

```java
@Bean
public UserDetailsService userDetailsService() {
    UserDetails user = User.builder()
        .username("user")
        .password(passwordEncoder().encode("password"))
        .roles("USER")
        .build();
    
    return new InMemoryUserDetailsManager(user);
}
```

### How it works:

**UserDetailsService** is the contract for loading user data. Your implementation uses `InMemoryUserDetailsManager` which stores users in memory.

**During Authentication:**
1. `DaoAuthenticationProvider` calls `userDetailsService.loadUserByUsername("user")`
2. `InMemoryUserDetailsManager` looks up user in its internal map
3. Returns `UserDetails` object containing:
   - Username: "user"
   - Password: "$2a$10$..." (BCrypt hash)
   - Authorities: `[ROLE_USER]` (Spring adds "ROLE_" prefix to roles)
   - Account status flags (enabled, not expired, etc.)

**In production**, you'd replace this with:
- `JdbcUserDetailsManager` (database lookup)
- Custom implementation querying your user repository

## 6. Password Encoding

```java
@Bean
public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
}
```

### BCrypt Deep Dive:

**Hashing Process:**
- Uses Blowfish cipher-based hashing
- Includes random **salt** (stored in hash output)
- Configurable **work factor** (default 10 = 2^10 iterations)
- Each hash takes ~100ms (intentionally slow to prevent brute force)

**Hash Format:**
```
$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy
 |  |  |                      |
 |  |  |                      +-- 31-character hash
 |  |  +-------------------------22-character salt
 |  +----------------------------work factor (10)
 +-------------------------------algorithm version (2a)
```

**Why it's secure:**
- Salt prevents rainbow table attacks
- High work factor prevents brute force
- Same password produces different hashes each time (due to random salt)

**During login:**
```java
// User enters: "password"
// Stored hash: "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"

boolean matches = passwordEncoder.matches("password", storedHash);
// BCrypt extracts salt and work factor from storedHash
// Hashes input password with same salt and work factor
// Compares results → returns true if match
```

## 7. CSRF Protection - The Critical Part

```java
.csrf(csrf -> csrf
    .ignoringRequestMatchers("/api/unsafe/**")
)
```

### How CSRF Protection Works:

**Filter Added:** `CsrfFilter` (runs early in chain)

**Token Generation (on first request):**
1. User visits page requiring CSRF protection
2. `CsrfFilter` checks if CSRF token exists in session
3. If not, generates new `CsrfToken`:
   ```java
   CsrfToken token = new DefaultCsrfToken(
       "X-CSRF-TOKEN",           // header name
       "_csrf",                  // parameter name
       UUID.randomUUID().toString()  // token value
   );
   ```
4. Stores token in `HttpSession` under attribute `HttpSessionCsrfTokenRepository.class.getName() + ".CSRF_TOKEN"`
5. Makes token available to view as request attribute

**Thymeleaf Integration:**
```html
<!-- Thymeleaf automatically adds this to forms -->
<form th:action="@{/transfer}" method="post">
    <input type="hidden" name="_csrf" value="3c5e8f2a-..." />
    <!-- other fields -->
</form>
```

**Token Validation (on POST request):**

```
POST /transfer
Content-Type: application/x-www-form-urlencoded

toAccount=123&amount=100&_csrf=3c5e8f2a-...
    ↓
CsrfFilter.doFilterInternal()
    ↓
1. Retrieves expected token from session
2. Extracts actual token from request:
   - First checks header: X-CSRF-TOKEN
   - Falls back to parameter: _csrf
3. Compares: actualToken.equals(expectedToken)
    ↓
If match → continue to next filter
If no match → throw AccessDeniedException
    ↓ (caught by ExceptionTranslationFilter)
Return 403 Forbidden
```

**Why Your Vulnerable Endpoint Works:**

```java
.ignoringRequestMatchers("/api/unsafe/**")
```

This tells `CsrfFilter` to skip validation for `/api/unsafe/**` URLs:

```java
// Simplified CsrfFilter logic
protected void doFilterInternal(HttpServletRequest request, ...) {
    if (requireCsrfProtectionMatcher.matches(request)) {
        // Validate token
    } else {
        // Skip validation - DANGEROUS!
    }
}
```

### CSRF Attack Prevention Flow:

**Protected Endpoint (/transfer):**
```
Attacker Site                      Your App
    |                                 |
    | POST /transfer                  |
    | toAccount=attacker              |
    | amount=1000                     |
    | (NO _csrf token)                |
    |-------------------------------->|
    |                                 |
    |                         CsrfFilter checks
    |                         Token missing!
    |                                 |
    |       403 Forbidden             |
    |<--------------------------------|
```

**Vulnerable Endpoint (/api/unsafe/transfer):**
```
Attacker Site                      Your App
    |                                 |
    | POST /api/unsafe/transfer       |
    | toAccount=attacker              |
    | amount=1000                     |
    |-------------------------------->|
    |                                 |
    |                         CsrfFilter skips
    |                         (ignoringRequestMatchers)
    |                                 |
    |       200 OK                    |
    |<--------------------------------|
    Attack succeeds!
```

## 8. Complete Request Flow Example

**Scenario: User transfers money**

```
1. Browser → GET /dashboard
   ↓
2. SecurityContextPersistenceFilter loads SecurityContext from session
   ↓ (no authentication found)
3. FilterSecurityInterceptor checks authorization
   ↓ (requires authenticated user)
4. AccessDeniedException thrown
   ↓
5. ExceptionTranslationFilter catches exception
   ↓
6. Saves original request (/dashboard) in RequestCache
   ↓
7. Redirects to /login
   ↓
8. Browser → GET /login
   ↓
9. Login page rendered with CSRF token
   ↓
10. Browser → POST /login
    username=user&password=password&_csrf=abc123
   ↓
11. CsrfFilter validates token ✓
   ↓
12. UsernamePasswordAuthenticationFilter processes login
   ↓
13. Calls AuthenticationManager.authenticate()
   ↓
14. DaoAuthenticationProvider calls userDetailsService.loadUserByUsername("user")
   ↓
15. Returns UserDetails with BCrypt hash
   ↓
16. BCrypt validates password ✓
   ↓
17. Creates authenticated UsernamePasswordAuthenticationToken
   ↓
18. SecurityContext.setAuthentication(token)
   ↓
19. SecurityContextPersistenceFilter saves context to session
   ↓
20. Redirects to /dashboard
   ↓
21. Browser → GET /dashboard (with JSESSIONID cookie)
   ↓
22. SecurityContextPersistenceFilter loads SecurityContext from session ✓
   ↓
23. FilterSecurityInterceptor checks authorization ✓
   ↓
24. Request reaches BankController.dashboard()
   ↓
25. Page rendered with new CSRF token for transfer form
   ↓
26. Browser → POST /transfer
    toAccount=123&amount=100&_csrf=xyz789
   ↓
27. CsrfFilter validates token ✓
   ↓
28. Request reaches BankController.transfer() ✓
```

## Key Security Concepts

### 1. Security Context
- Thread-local storage holding authentication
- Accessible via `SecurityContextHolder.getContext().getAuthentication()`
- Cleared after request completes

### 2. Session Management
- Authentication stored in `HttpSession`
- Session fixation protection enabled by default (creates new session ID after login)
- JSESSIONID cookie used to maintain session

### 3. Filter Chain Customization
Every configuration method adds/modifies filters:
- `.formLogin()` → adds `UsernamePasswordAuthenticationFilter`
- `.logout()` → adds `LogoutFilter`
- `.csrf()` → adds `CsrfFilter`
- `.authorizeHttpRequests()` → configures `AuthorizationFilter`

### 4. Stateful vs Stateless
Your app is **stateful**:
- Authentication stored in server-side session
- Requires session cookies
- CSRF protection necessary

For REST APIs, you'd use **stateless**:
- JWT tokens instead of sessions
- No CSRF protection needed
- Each request contains credentials

## Summary

Spring Security protects your application through a sophisticated filter chain that:
1. **Loads** security context from session
2. **Validates** CSRF tokens on state-changing requests
3. **Checks** if user is authenticated for protected resources
4. **Authenticates** users via form login with password hashing
5. **Stores** authentication in session for subsequent requests
6. **Makes authorization decisions** before allowing access to controllers

Your demo perfectly illustrates the difference: protected endpoints require valid CSRF tokens, while the unsafe endpoint bypasses this critical security check, making it vulnerable to cross-site request forgery attacks.

## Further Reading

- [Spring Security Reference Documentation](https://docs.spring.io/spring-security/reference/)
- [Spring Security Architecture](https://spring.io/guides/topicals/spring-security-architecture)
- [Understanding BCrypt](https://en.wikipedia.org/wiki/Bcrypt)
- [OWASP CSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
