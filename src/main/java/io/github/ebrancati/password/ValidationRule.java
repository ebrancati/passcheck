package io.github.ebrancati.password;

import java.util.function.Predicate;

/**
 * Represents a single password validation rule with its validation logic and error message.
 *
 * <p>Each rule contains:
 * <ul>
 * <li>A validation function with the validation logic to apply to passwords
 * <li>An error message to show when validation fails
 * </ul>
 */
class ValidationRule {
    private final Predicate<String> function;
    private final String errorMessage;

    ValidationRule(Predicate<String> function, String errorMessage) {
        this.function = function;
        this.errorMessage = errorMessage;
    }

    /**
     * Tests if the given password passes this validation rule.
     *
     * @return true if password passes the rule, false otherwise
     */
    boolean test(String password) {
        return function.test(password);
    }

    String getErrorMessage() {
        return errorMessage;
    }
}