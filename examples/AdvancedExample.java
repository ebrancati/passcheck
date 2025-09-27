import io.github.ebrancati.password.PasswordValidator;
import java.util.concurrent.CompletableFuture;

public class AdvancedExample {

    public static void main(String[] args) {

        PasswordValidator validator = new PasswordValidator()
            .lengthBetween(12, 50)
            .requireUppercase()
            .requireLowercase()
            .requireDigits()
            .forbidSpaces()
            .blacklistPasswords(new String[]{"password", "123456", "qwerty"})
            .matchPattern(".*[!@#$%].*") // Requires custom symbols (! @ # $ %) instead of requireSymbols() default set
            .forbidKnownBreaches();

        System.out.println("Test 1 - Password valid: " + validator.isValid("x3p$cY#c!Hm7"));

        List<String> errors = validator.getErrors("weak");
        if (errors.isEmpty()) System.out.println("Test 2 - Password is valid!");
        else                  System.out.println("Test 2 - Password is invalid. Errors: " + errors);
    }
}