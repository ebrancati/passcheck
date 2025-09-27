package io.github.ebrancati.password;

import java.util.List;
import java.util.concurrent.CompletableFuture;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.params.provider.CsvSource;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link PasswordValidator}.
 */
class PasswordValidatorTest {

    @Nested
    @DisplayName("Length Rules")
    class LengthRules {

        @ParameterizedTest
        @DisplayName("Minimum length")
        @CsvSource({
            "6, abc456,  true",  // exactly min
            "6, abc4567, true",  // longer
            "6, abc45,   false", // too short
            "1, '',      false", // too short
            "0, '',      true"   // no minimum
        })
        void testMinLength(int minLength, String password, boolean expected) {
            PasswordValidator validator = new PasswordValidator().minLength(minLength);
            assertEquals(expected, validator.isValid(password));
        }

        @ParameterizedTest
        @DisplayName("Maximum length")
        @CsvSource({
            "6, abc456,  true",  // exactly max
            "6, abc45,   true",  // shorter
            "6, abc4567, false"  // too long
        })
        void testMaxLength(int maxLength, String password, boolean expected) {
            PasswordValidator validator = new PasswordValidator().maxLength(maxLength);
            assertEquals(expected, validator.isValid(password));
        }

        @ParameterizedTest
        @DisplayName("Length between")
        @CsvSource({
            "1, 6, abc45,    true",  // in range
            "1, 6, a,        true",  // exactly min
            "1, 6, abc456,   true",  // exactly max
            "3, 3, abc,      true",  // exact match
            "5, 7, ab,       false", // too short
            "5, 7, abc45678, false", // too long
            "7, 5, test,     false"  // invalid: min > max
        })
        void testLengthBetween(int min, int max, String password, boolean expected) {
            PasswordValidator validator = new PasswordValidator().lengthBetween(min, max);
            assertEquals(expected, validator.isValid(password));
        }
    }

    @Nested
    @DisplayName("Character Requirements")
    class CharacterRequirements {

        @ParameterizedTest
        @DisplayName("Require letters")
        @CsvSource({
            "3, abc123,  true",  // exactly required
            "5, letters, true",  // more than required
            "5, lett1,   false", // too few
            "1, 123,     false", // missing letters
            "0, 12345,   true",  // no minimum
        })
        void testRequireLetters(int count, String password, boolean expected) {
            PasswordValidator validator = new PasswordValidator().requireLetters(count);
            assertEquals(expected, validator.isValid(password));
        }

        @ParameterizedTest
        @DisplayName("Require uppercase")
        @CsvSource({
            "1, Password,    true",  // exactly required
            "2, PASSword,    true",  // more than required
            "2, Password,    false", // too few
            "1, nouppercase, false", // missing uppercase
            "0, nouppercase, true",  // no minimum
        })
        void testRequireUppercase(int count, String password, boolean expected) {
            PasswordValidator validator = new PasswordValidator().requireUppercase(count);
            assertEquals(expected, validator.isValid(password));
        }

        @ParameterizedTest
        @DisplayName("Require lowercase")
        @CsvSource({
            "7, Password,    true",  // exactly required
            "2, PASSword,    true",  // more than required
            "2, PASSWORd,    false", // too few
            "1, NOLOWERCASE, false", // missing lowercase
            "0, NOLOWERCASE, true",  // no minimum
        })
        void testRequireLowercase(int count, String password, boolean expected) {
            PasswordValidator validator = new PasswordValidator().requireLowercase(count);
            assertEquals(expected, validator.isValid(password));
        }

        @ParameterizedTest
        @DisplayName("Require digits")
        @CsvSource({
            "3, test123,    true",  // exactly required
            "5, test123456, true",  // more than required
            "5, test12,     false", // too few
            "1, test,       false", // missing digits
            "0, test,       true",  // no minimum
        })
        void testRequireDigits(int count, String password, boolean expected) {
            PasswordValidator validator = new PasswordValidator().requireDigits(count);
            assertEquals(expected, validator.isValid(password));
        }

        @ParameterizedTest
        @DisplayName("Require symbols")
        @CsvSource({
            "2, test!@,     true", // exactly required
            "5, test!@#$%^, true", // more than required
            "2, test!,      false", // too few
            "1, nosymbols,  false", // missing symbols
            "0, nosymbols,  true",  // no minimum
        })
        void testRequireSymbols(int count, String password, boolean expected) {
            PasswordValidator validator = new PasswordValidator().requireSymbols(count);
            assertEquals(expected, validator.isValid(password));
        }

        @Test
        @DisplayName("Default parameters for character requirements")
        void testDefaultParameters() {
            // Test methods without explicit count parameters (should default to 1)
            PasswordValidator validator = new PasswordValidator()
                .requireUppercase()
                .requireLowercase()
                .requireDigits()
                .requireSymbols();

            assertTrue(validator.isValid("Aa1!"));
            assertFalse(validator.isValid("aa1!")); // Missing uppercase
            assertFalse(validator.isValid("AA1!")); // Missing lowercase
            assertFalse(validator.isValid("Aa!"));  // Missing digit
            assertFalse(validator.isValid("Aa1"));  // Missing symbol
        }
    }

    @Nested
    @DisplayName("Content Validation")
    class ContentValidation {

        @ParameterizedTest
        @DisplayName("Forbid spaces")
        @CsvSource({
            "nospaces,     true",
            "'has spaces', false",
            "'          ', false",
        })
        void testForbidSpaces(String password, boolean expected) {
            PasswordValidator validator = new PasswordValidator().forbidSpaces();
            assertEquals(expected, validator.isValid(password));
        }

        @ParameterizedTest
        @DisplayName("Forbid blacklisted passwords")
        @CsvSource({
            "randomPsw, true",
            "password,  false",
            "qwerty,    false",
            "123456,    false",
        })
        void testBlacklistPasswords(String password, boolean expected) {
            PasswordValidator validator = new PasswordValidator()
                .blacklistPasswords(new String[]{"password", "qwerty", "123456"});
            assertEquals(expected, validator.isValid(password));
        }

        @ParameterizedTest
        @DisplayName("Match required pattern")
        @CsvSource({
            "'p@ssword!', true",
            "'test#',     true",
            "password,    false",
        })
        void testMatchPattern(String password, boolean expected) {
            PasswordValidator validator = new PasswordValidator()
                .matchPattern(".*[!@#].*"); // Must contain at least one of: ! @ #
            assertEquals(expected, validator.isValid(password));
        }

        @ParameterizedTest
        @DisplayName("Forbid N consecutive digits")
        @CsvSource({
            "pass123,    true",
            "simple,     true", // no digits
            "test12345,  false",
            "abc1234xyz, false",  
        })
        void testForbidDigitsPattern(String password, boolean expected) {
            PasswordValidator validator = new PasswordValidator().forbidPattern("\\d{4,}");
            assertEquals(expected, validator.isValid(password));
        }

        @ParameterizedTest
        @DisplayName("Forbid whitespace")
        @CsvSource({
            "nowhitespaces, true",
            "'has spaces',  false",
            "'tab\there',   false",
            "'new\nline',   false",
        })
        void testForbidWhitespacePattern(String password, boolean expected) {
            PasswordValidator validator = new PasswordValidator().forbidPattern("\\s+");
            assertEquals(expected, validator.isValid(password));
        }
    }

    @Nested
    @DisplayName("Breach Checking")
    class BreachChecking {

        @Test
        @DisplayName("Forbid known breaches (network dependent)")
        void testForbidKnownBreaches() {
            PasswordValidator schema = new PasswordValidator().forbidKnownBreaches();

            try {
                boolean result = schema.isValid("123456"); // Known compromised password
                assertFalse(result);
            } catch (RuntimeException e) {
                fail("Network error: " + e.getMessage());
            }
        }
    }

    @Nested
    @DisplayName("Validation Methods")
    class ValidationMethods {

        @Test
        @DisplayName("isValid method returns boolean")
        void testIsValidMethod() {
            PasswordValidator schema = new PasswordValidator()
                .minLength(8)
                .maxLength(25)
                .requireUppercase()
                .requireDigits()
                .requireSymbols()
                .forbidSpaces();

            assertTrue(schema.isValid("C0mpl3xP@sswrd"));
            assertFalse(schema.isValid("weak"));
        }

        @Test
        @DisplayName("getErrors method returns error list")
        void testGetErrors() {
            PasswordValidator schema = new PasswordValidator()
                .minLength(8)
                .maxLength(25)
                .requireUppercase()
                .requireDigits()
                .matchPattern(".*[!@#$%^&*].*")
                .forbidSpaces();

            List<String> errors = schema.getErrors("weak");
            assertFalse(errors.isEmpty(), "Should have validation errors for weak password");
            assertTrue(errors.size() > 0, "Should contain specific error messages");

            List<String> noErrors = schema.getErrors("C0mpl3xP@sswrd");
            assertTrue(noErrors.isEmpty(), "Password meeting all requirements should have no validation errors");
        }
    }

    @Nested
    @DisplayName("Async Methods")
    class AsyncMethods {

        @Test
        @DisplayName("isValidAsync returns CompletableFuture<Boolean>")
        void testIsValidAsync() throws Exception {
            PasswordValidator schema = new PasswordValidator()
                .minLength(8)
                .maxLength(25)
                .requireUppercase()
                .requireDigits()
                .requireSymbols(2)
                .forbidSpaces();

            CompletableFuture<Boolean> future = schema.isValidAsync("C0mp!3xP@sswrd");
            Boolean result = future.get();
            assertTrue(result);

            future = schema.isValidAsync("weak");
            result = future.get();
            assertFalse(result);
        }

        @Test
        @DisplayName("getErrorsAsync returns CompletableFuture<List<String>>")
        void testGetErrorsAsync() throws Exception {
            PasswordValidator schema = new PasswordValidator()
                .minLength(8)
                .maxLength(25)
                .requireUppercase()
                .requireDigits()
                .requireSymbols(2)
                .matchPattern(".*[!@#$%^&*].*")
                .forbidSpaces();

            CompletableFuture<List<String>> future = schema.getErrorsAsync("weak");
            List<String> errors = future.get();
            assertFalse(errors.isEmpty());

            future = schema.getErrorsAsync("C0mp!3xP@sswrd");
            errors = future.get();
            assertTrue(errors.isEmpty());
        }
    }

    @Nested
    @DisplayName("Custom Error Messages")
    class CustomMessages {

        @Test
        @DisplayName("Custom messages override default")
        void testCustomMessages() {
            PasswordValidator validator = new PasswordValidator()
                .minLength(8, "Password too short")
                .requireUppercase("Missing uppercase letter")
                .requireDigits(2, "Need at least 2 digits");

            List<String> errors = validator.getErrors("test");
            assertEquals(3, errors.size());
            assertTrue(errors.contains("Password too short"));
            assertTrue(errors.contains("Missing uppercase letter"));
            assertTrue(errors.contains("Need at least 2 digits"));
        }
    }

    @Nested
    @DisplayName("Exception Handling")
    class ExceptionHandling {

        @Test
        @DisplayName("Reject null password")
        void testNullPassword() {
            PasswordValidator validator = new PasswordValidator().minLength(8);
            assertThrows(IllegalArgumentException.class, () -> validator.isValid(null));
            assertThrows(IllegalArgumentException.class, () -> validator.getErrors(null));
        }

        @ParameterizedTest
        @DisplayName("Handling special character")
        @ValueSource(strings = {"", " ", "\t", "\n", "🔒", "пароль", "密码"})
        void testSpecialCharacters(String input) {
            PasswordValidator validator = new PasswordValidator().minLength(1);
            assertDoesNotThrow(() -> validator.isValid(input));
            assertDoesNotThrow(() -> validator.getErrors(input));
        }
    }
}