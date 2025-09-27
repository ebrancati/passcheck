# passcheck

Simple Java password validation library with custom rules and breach detection

## Add Dependency

```xml
<dependency>
    <groupId>io.github.ebrancati</groupId>
    <artifactId>passcheck</artifactId>
    <version>0.1.0</version>
</dependency>
```

## Getting Started

```java
import io.github.ebrancati.password.PasswordValidator;

// Set up validation rules 
PasswordValidator validator = new PasswordValidator()
    .minLength(8)           // At least 8 characters
    .maxLength(40)          // At most 40 characters
    .requireUppercase()     // At least 1 uppercase letter
    .requireLowercase()     // At least 1 lowercase letter
    .requireDigits(2)       // At least 2 digits
    .requireSymbols()       // At least 1 special character
    .forbidSpaces()         // No spaces allowed
    .forbidKnownBreaches(); // Reject passwords found in data breaches

// Validate password
String password = "Kp9$mN2wX7#f";
boolean isValid = validator.isValid(password); // Check if password passes all rules
List<String> errors = validator.getErrors(password); // Returns error messages if invalid
```

## Examples

**Basic:**
```java
boolean isValid = new PasswordValidator().minLength(6).requireDigits().isValid("psw456");
System.out.println("Password valid: " + isValid);
```

**Advanced:**
```java
PasswordValidator validator = new PasswordValidator()
    .lengthBetween(12, 50)
    .requireUppercase()
    .requireLowercase()
    .requireDigits()
    .forbidSpaces()
    .forbidPattern(".*\\d{3,}.*") // No 3+ consecutive digits
    .blacklistPasswords(new String[]{"password", "qwerty", "anything"})
    .forbidKnownBreaches();

List<String> errors = validator.getErrors("Nt8%xB5jW2#m");
if (errors.isEmpty()) System.out.println("Password is valid!");
else                  System.out.println("Password is invalid. Errors: " + errors);
```

## Customization

### Custom Error Messages

All validation methods accept custom error messages:

```java
PasswordValidator validator = new PasswordValidator()
    .lengthBetween(12, 50, "Choose a password between 12-50 characters")
    .requireUppercase("Include at least one capital letter")
    .requireDigits(2, "Add at least 2 numbers")
    .forbidSpaces("Spaces are not allowed");

List<String> errors = validator.getErrors("weakpsw");
System.out.println(errors);
```

**Output:**
```
[
  "Choose a password between 12-50 characters",
  "Include at least one capital letter",
  "Add at least 2 numbers"
]
```

### Custom Symbol Requirements

Control which symbols are allowed in passwords:

```java
// Using default symbol set
PasswordValidator anySymbols = new PasswordValidator()
    .requireSymbols(); // Requires one of: !@#$%^&*()_+-=[]{}|;:,.<>?`~"'\€£¥₹§±

// Require specific symbols
PasswordValidator specificSymbols = new PasswordValidator()
    .matchPattern(".*[!?@#$%].*"); // Requires one of: ! ? @ # $ %
```

## API Reference

### Length Validation
| Rule | Description |
|------|-------------|
| `minLength(length, [errorMessage])` | Requires minimum password length |
| `maxLength(length, [errorMessage])` | Requires maximum password length |
| `lengthBetween(min, max, [errorMessage])` | Requires password length within specified range |

### Character Requirements
| Rule | Description |
|------|-------------|
| `requireLetters([count], [errorMessage])` | Requires letters (default: 1) |
| `requireUppercase([count], [errorMessage])` | Requires uppercase letters (default: 1) |
| `requireLowercase([count], [errorMessage])` | Requires lowercase letters (default: 1) |
| `requireDigits([count], [errorMessage])` | Requires digits (default: 1) |
| `requireSymbols([count], [errorMessage])` | Requires symbols (default: 1) |

### Content Validation
| Rule | Description |
|------|-------------|
| `forbidSpaces([errorMessage])` | Blocks spaces in password |
| `blacklistPasswords(passwords[], [errorMessage])` | Blocks specified passwords |
| `matchPattern(regex, [errorMessage])` | Requires password to match regex pattern |
| `forbidPattern(regex, [errorMessage])` | Blocks password from matching regex pattern |

### Breach Detection
| Rule | Description |
|------|-------------|
| `forbidKnownBreaches([errorMessage])` | Reject passwords found in data breaches |

### Validation Methods
| Method | Description |
|--------|-------------|
| `isValid(password)` | Returns true if password passes all rules |
| `getErrors(password)` | Returns list of error messages (empty if valid) |
| `isValidAsync(password)` | Returns CompletableFuture<Boolean> for async validation |
| `getErrorsAsync(password)` | Returns CompletableFuture<List<String>> for async error list |

## Requirements

Java 11+

## License

[MIT](LICENSE)