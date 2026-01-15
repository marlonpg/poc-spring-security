# Spring Security CSRF Protection Demo

A practical demonstration of CSRF (Cross-Site Request Forgery) protection using Spring Security. This project shows both protected and vulnerable endpoints to help understand how CSRF attacks work and how Spring Security prevents them.

## What You'll Learn

- How CSRF attacks exploit authenticated sessions
- How Spring Security's CSRF protection works
- Difference between protected and unprotected endpoints
- Best practices for implementing CSRF defense

## Quick Start

### Prerequisites
- Java 17 or higher
- Maven 3.6+

### Running the Application

```bash
# Clone and navigate to the project
cd poc-spring-security

# Run the application
mvnw spring-boot:run
```

The application will start on `http://localhost:8080`

### Demo Credentials
- **Username:** `user`
- **Password:** `password`

## Demo Walkthrough

### 1. Login and Explore Protected Dashboard
1. Navigate to `http://localhost:8080/login`
2. Login with the demo credentials
3. You'll see the **Dashboard** with CSRF protection enabled
4. Try making a transfer and observe the CSRF token in DevTools

### 2. View the Vulnerable Page
1. Click "View Vulnerable Page" on the dashboard
2. See the `/api/unsafe/transfer` endpoint that has CSRF protection disabled
3. Click "Simulate CSRF Attack" to see how an attacker could exploit this

### 3. Compare the Difference
- **Protected Endpoint** (`/transfer`): Requires CSRF token, safe from attacks
- **Unprotected Endpoint** (`/api/unsafe/transfer`): No token required, vulnerable

## Key Components

### Security Configuration
[SecurityConfig.java](src/main/java/com/example/SecurityConfig.java) shows:
- CSRF protection enabled by default
- Specific endpoint exclusions for demonstration
- Form-based authentication setup

### Controller
[BankController.java](src/main/java/com/example/BankController.java) includes:
- Protected POST endpoint (`/transfer`)
- Vulnerable API endpoint (`/api/unsafe/transfer`)
- Balance tracking to demonstrate impact

### Templates
- **login.html**: Login form (auto-generated CSRF token)
- **dashboard.html**: Protected transfer form with CSRF token
- **vulnerable.html**: Demonstrates unprotected endpoint and attack simulation

## Testing CSRF Protection

### Test 1: Protected Endpoint
```bash
# This will fail without CSRF token
curl -X POST http://localhost:8080/transfer \
  -d "toAccount=test&amount=100" \
  -b cookies.txt
  
# Expected: 403 Forbidden
```

### Test 2: Unprotected Endpoint
```bash
# This will succeed (vulnerability demo)
curl -X POST http://localhost:8080/api/unsafe/transfer \
  -d "toAccount=test&amount=100" \
  -b cookies.txt
  
# Expected: Success (showing the vulnerability)
```

## How Spring Security CSRF Protection Works

1. **Token Generation**: Spring Security generates a unique CSRF token per session
2. **Token Inclusion**: Thymeleaf automatically includes the token in forms
3. **Token Validation**: Server validates token on state-changing requests (POST, PUT, DELETE)
4. **Request Rejection**: Invalid/missing tokens result in 403 Forbidden

### In Your Code
```html
<!-- Thymeleaf automatically adds CSRF token -->
<form th:action="@{/transfer}" method="post">
    <input type="hidden" name="_csrf" value="generated-token-here">
    <!-- Other form fields -->
</form>
```

## Common CSRF Attack Vectors

1. **Malicious Forms**: Hidden forms auto-submitted from attacker sites
2. **Image Tags**: GET requests disguised as image loads
3. **AJAX Requests**: JavaScript-based cross-origin requests
4. **Email Links**: Crafted URLs in phishing emails

See [CSRF-README.md](CSRF-README.md) for detailed attack examples.

## CSRF Protection Best Practices

1. Keep CSRF protection enabled (default in Spring Security)
2. Use CSRF tokens for all state-changing operations
3. Never disable CSRF for authenticated endpoints
4. Use `SameSite` cookie attribute
5. Validate the `Origin` and `Referer` headers
6. Implement proper CORS configuration

## When to Disable CSRF Protection

Only disable CSRF for:
- Stateless REST APIs using token-based authentication (JWT, OAuth2)
- Public webhooks
- Non-browser clients exclusively

**Never disable for:**
- Form-based authentication
- Session-based authentication
- Cookie-based authentication

## Additional Resources

- [Spring Security CSRF Documentation](https://docs.spring.io/spring-security/reference/features/exploits/csrf.html)
- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [CSRF-README.md](CSRF-README.md) - Detailed CSRF attack examples

## Educational Purpose

This project is designed for **educational purposes only**. The vulnerable endpoint is intentionally created to demonstrate CSRF attacks. Never implement such patterns in production applications.

## License

This is a demo project for educational purposes.