package io.github.ebrancati.passcheck;

final class ErrorMessages {

    private ErrorMessages() {}

    static final String MIN_LENGTH = "Password must be at least %d characters long";
    static final String MAX_LENGTH = "Password must be at most %d characters long";

    static final String REQUIRE_LETTERS = "Password must contain at least %d letter%s";
    static final String REQUIRE_UPPERCASE = "Password must contain at least %d uppercase letter%s";
    static final String REQUIRE_LOWERCASE = "Password must contain at least %d lowercase letter%s";
    static final String REQUIRE_DIGITS = "Password must contain at least %d digit%s";
    static final String REQUIRE_SYMBOLS = "Password must contain at least %d symbol%s: %s";

    static final String FORBID_SPACES = "Password must not contain spaces";
    static final String BLACKLISTED = "Password is blacklisted and not allowed";
    static final String PATTERN_REQUIRED = "Password must match required format";
    static final String PATTERN_FORBIDDEN = "Password contains forbidden pattern";

    static final String BREACH_FOUND = "Password found in %,d data breach%s";

    static final String NULL_PASSWORD = "Password cannot be null";
}