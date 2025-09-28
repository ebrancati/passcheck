package io.github.ebrancati.passcheck;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import java.util.concurrent.CompletableFuture;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.nio.charset.StandardCharsets;

/**
 * Validates passwords against configurable rules.
 *
 * @see <a href="https://github.com/ebrancati/passcheck#readme">Documentation and Examples</a>
 */
public class PasswordValidator {

    private final List<ValidationRule> rules = new ArrayList<>();

    // Length validation

    public PasswordValidator minLength(int length) {
        return minLength(length, String.format(ErrorMessages.MIN_LENGTH, length));
    }

    public PasswordValidator minLength(int length, String errorMessage) {
        rules.add(new ValidationRule(
            password -> password.length() >= length,
            errorMessage
        ));
        return this;
    }

    public PasswordValidator maxLength(int length) {
        return maxLength(length, String.format(ErrorMessages.MAX_LENGTH, length));
    }

    public PasswordValidator maxLength(int length, String errorMessage) {
        rules.add(new ValidationRule(
            password -> password.length() <= length,
            errorMessage
        ));
        return this;
    }

    public PasswordValidator lengthBetween(int min, int max) {
        return minLength(min).maxLength(max);
    }

    public PasswordValidator lengthBetween(int min, int max, String errorMessage) {
        rules.add(new ValidationRule(
            password -> password.length() >= min && password.length() <= max,
            errorMessage
        ));
        return this;
    }

    // Character requirements

    public PasswordValidator requireLetters() {
        return requireLetters(1);
    }

    public PasswordValidator requireLetters(String errorMessage) {
        return requireLetters(1, errorMessage);
    }

    public PasswordValidator requireLetters(int count) {
        return requireLetters(count, String.format(ErrorMessages.REQUIRE_LETTERS, count, count > 1 ? "s" : ""));
    }

    public PasswordValidator requireLetters(int count, String errorMessage) {
        rules.add(new ValidationRule(
            password -> countLetters(password) >= count,
            errorMessage
        ));
        return this;
    }

    public PasswordValidator requireUppercase() {
        return requireUppercase(1);
    }

    public PasswordValidator requireUppercase(String errorMessage) {
        return requireUppercase(1, errorMessage);
    }

    public PasswordValidator requireUppercase(int count) {
        return requireUppercase(count, String.format(ErrorMessages.REQUIRE_UPPERCASE, count, count > 1 ? "s" : ""));
    }

    public PasswordValidator requireUppercase(int count, String errorMessage) {
        rules.add(new ValidationRule(
            password -> countUppercase(password) >= count,
            errorMessage
        ));
        return this;
    }

    public PasswordValidator requireLowercase() {
        return requireLowercase(1);
    }

    public PasswordValidator requireLowercase(String errorMessage) {
        return requireLowercase(1, errorMessage);
    }

    public PasswordValidator requireLowercase(int count) {
        return requireLowercase(count, String.format(ErrorMessages.REQUIRE_LOWERCASE, count, count > 1 ? "s" : ""));
    }

    public PasswordValidator requireLowercase(int count, String errorMessage) {
        rules.add(new ValidationRule(
            password -> countLowercase(password) >= count,
            errorMessage
        ));
        return this;
    }

    public PasswordValidator requireDigits() {
        return requireDigits(1);
    }

    public PasswordValidator requireDigits(String errorMessage) {
        return requireDigits(1, errorMessage);
    }

    public PasswordValidator requireDigits(int count) {
        return requireDigits(count, String.format(ErrorMessages.REQUIRE_DIGITS, count, count > 1 ? "s" : ""));
    }

    public PasswordValidator requireDigits(int count, String errorMessage) {
        rules.add(new ValidationRule(
            password -> countDigits(password) >= count,
            errorMessage
        ));
        return this;
    }

    public PasswordValidator requireSymbols() {
        return requireSymbols(1);
    }

    public PasswordValidator requireSymbols(String errorMessage) {
        return requireSymbols(1, errorMessage);
    }

    public PasswordValidator requireSymbols(int count) {
        return requireSymbols(count, String.format(ErrorMessages.REQUIRE_SYMBOLS, count, count > 1 ? "s" : "", getValidSymbols()));
    }

    public PasswordValidator requireSymbols(int count, String errorMessage) {
        rules.add(new ValidationRule(
            password -> countSymbols(password, getValidSymbols()) >= count,
            errorMessage
        ));
        return this;
    }

    // Content validation

    public PasswordValidator forbidSpaces() {
        return forbidSpaces(ErrorMessages.FORBID_SPACES);
    }

    public PasswordValidator forbidSpaces(String errorMessage) {
        rules.add(new ValidationRule(
            password -> !password.contains(" "),
            errorMessage
        ));
        return this;
    }

    public PasswordValidator blacklistPasswords(String[] passwords) {
        return blacklistPasswords(passwords, ErrorMessages.BLACKLISTED);
    }

    public PasswordValidator blacklistPasswords(String[] passwords, String errorMessage) {
        Set<String> forbidden = Set.of(passwords);
        rules.add(new ValidationRule(
            password -> !forbidden.contains(password),
            errorMessage
        ));
        return this;
    }

    /**
     * @throws PatternSyntaxException if regex is invalid
     */
    public PasswordValidator matchPattern(String regex) {
        return matchPattern(regex, ErrorMessages.PATTERN_REQUIRED);
    }

    public PasswordValidator matchPattern(String regex, String errorMessage) {
        Pattern pattern = Pattern.compile(regex);
        rules.add(new ValidationRule(
            password -> pattern.matcher(password).find(),
            errorMessage
        ));
        return this;
    }

    /**
     * @throws PatternSyntaxException if regex is invalid
     */
    public PasswordValidator forbidPattern(String regex) {
        return forbidPattern(regex, ErrorMessages.PATTERN_FORBIDDEN);
    }

    public PasswordValidator forbidPattern(String regex, String errorMessage) {
        Pattern pattern = Pattern.compile(regex);
        rules.add(new ValidationRule(
            password -> !pattern.matcher(password).find(),
            errorMessage
        ));
        return this;
    }

    // Breach detection

    /**
     * Forbids passwords found in known data breaches using HaveIBeenPwned API.
     * Uses k-anonymity to protect privacy. Only the first few characters
     * of the password's SHA-1 hash are sent to the API.
     *
     * @throws RuntimeException if breach checking fails
     */
    public PasswordValidator forbidKnownBreaches() {
        return forbidKnownBreaches(ErrorMessages.BREACH_FOUND);
    }

    public PasswordValidator forbidKnownBreaches(String errorMessage) {
        rules.add(new ValidationRule(
            password -> {
                try {
                    return getBreachCount(password) == 0;
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            },
            errorMessage
        ));
        return this;
    }

    // Validation methods

    /**
     * Checks password against all validation rules.
     * For detailed error information, use {@link #getErrors(String)} instead.
     *
     * @return true if password passes all rules, false otherwise
     * @throws RuntimeException if breach checking fails
     */
    public boolean isValid(String password) {
        validateInput(password);
        return getErrors(password).isEmpty();
    }

    /**
     * Checks password against all validation rules.
     *
     * @return empty list if password is valid, otherwise list of error messages
     * @throws RuntimeException if breach checking fails
     */
    public List<String> getErrors(String password) {
        validateInput(password);

        List<String> errors = new ArrayList<>();

        for (ValidationRule rule : rules) {
            // Apply validation rule and collect any errors
            addValidationError(errors, rule, password);
        }
        return errors;
    }

    /**
     * Asynchronously checks password against all validation rules.
     * For detailed error information, use {@link #getErrorsAsync(String)} instead.
     *
     * @return CompletableFuture that resolves to true if password passes all rules, false otherwise
     * @throws RuntimeException if breach checking fails
     */
    public CompletableFuture<Boolean> isValidAsync(String password) {
        return getErrorsAsync(password).thenApply(List::isEmpty);
    }

    /**
     * Asynchronously checks password against all validation rules.
     *
     * @return CompletableFuture that resolves to empty list if password is valid, otherwise list of error messages
     * @throws RuntimeException if breach checking fails
     */
    public CompletableFuture<List<String>> getErrorsAsync(String password) {
        return CompletableFuture.supplyAsync(() -> getErrors(password));
    }

    // Helper methods

    private int countLetters(String password) {
        return (int) password.chars().filter(Character::isLetter).count();
    }

    private int countUppercase(String password) {
        return (int) password.chars().filter(Character::isUpperCase).count();
    }

    private int countLowercase(String password) {
        return (int) password.chars().filter(Character::isLowerCase).count();
    }

    private int countDigits(String password) {
        return (int) password.chars().filter(Character::isDigit).count();
    }

    private int countSymbols(String password, String allowedSymbols) {
        return (int) password.chars().filter(c -> allowedSymbols.indexOf(c) >= 0).count();
    }

    private String getValidSymbols() {
        return "!@#$%^&*()_+-=[]{}|;:,.<>?`~\"'\\€£¥₹§±";
    }

    private int getBreachCount(String password) throws IOException {
        final String BREACH_API_URL = "https://api.pwnedpasswords.com/range/";
        final String USER_AGENT = "passcheck/0.1.0";
        final int HASH_PREFIX_LENGTH = 5;

        HttpClient httpClient = createDefaultHttpClient();

        try {
            // Hash the password and split for k-anonymity protocol
            String hash = calculateSha1Hash(password);
            String hashPrefix = hash.substring(0, HASH_PREFIX_LENGTH);  // Send only first 5 chars
            String hashSuffix = hash.substring(HASH_PREFIX_LENGTH);  // Keep remaining 27 chars secret

            // Request all hashes that start with the same prefix
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(BREACH_API_URL + hashPrefix))
                    .header("User-Agent", USER_AGENT)
                    .timeout(Duration.ofSeconds(5))
                    .GET()
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            // Parse response and find exact match for our password
            // Response format: "SUFFIX:COUNT" per line
            // Example: "11DA5D5B4BC6D497FFA98491E38:3847"
            return response.body().lines()
                    .map(line -> line.split(":"))
                    .filter(hashParts -> isWellFormedAndMatches(hashParts, hashSuffix))
                    .mapToInt(hashParts -> Integer.parseInt(hashParts[1]))
                    .findFirst()
                    .orElse(0);  // Not found = not breached

        } catch (Exception e) {
            throw new IOException("Failed to check password against breach database", e);
        }
    }

    private HttpClient createDefaultHttpClient() {
        return HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                .build();
    }

    private String calculateSha1Hash(String input) {
        byte[] hashBytes = generateSha1Bytes(input);
        return convertBytesToHex(hashBytes);
    }

    private byte[] generateSha1Bytes(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-1");
            return digest.digest(input.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-1 algorithm not available", e);
        }
    }

    private String convertBytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02X", b));
        }
        return result.toString();
    }

    private boolean isWellFormedAndMatches(String[] splitLine, String targetSuffix) {
        // Check if split API response line has format [suffix, count] and matches our hash suffix
        return splitLine.length == 2 && splitLine[0].equalsIgnoreCase(targetSuffix);
    }

    private void validateInput(String password) {
        if (password == null) {
            throw new IllegalArgumentException(ErrorMessages.NULL_PASSWORD);
        }
    }

    private void addValidationError(List<String> errors, ValidationRule rule, String password) {
        // Breach rules need special handling to avoid duplicate API calls
        if (isBreachRule(rule)) {
            addBreachError(errors, password);
        } else {
            addStandardError(errors, rule, password);
        }
    }

    private boolean isBreachRule(ValidationRule rule) {
        return rule.getErrorMessage().equals(ErrorMessages.BREACH_FOUND);
    }

    private void addBreachError(List<String> errors, String password) {
        try {
            int count = getBreachCount(password);
            if (count > 0) {
                errors.add(formatBreachMessage(count));
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void addStandardError(List<String> errors, ValidationRule rule, String password) {
        if (!rule.test(password)) {
            errors.add(rule.getErrorMessage());
        }
    }

    private String formatBreachMessage(int count) {
        return String.format(ErrorMessages.BREACH_FOUND, count, count == 1 ? "" : "es");
    }
}