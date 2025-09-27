import io.github.ebrancati.password.PasswordValidator;
import java.util.List;

public class AsyncExample {

    public static void main(String[] args) {

        PasswordValidator validator = new PasswordValidator()
            .minLength(8)
            .requireUppercase()
            .requireDigits();

        validator.isValidAsync("V4lidpsw")
            .thenAccept(isValid -> System.out.println("Test 1 - Password valid: " + isValid));

        validator.getErrorsAsync("weak")
            .thenAccept(errors -> {
                if (errors.isEmpty()) System.out.println("Test 2 - Password is valid!");
                else                  System.out.println("Test 2 - Validation errors: " + errors);
            });

        // Keep main alive to see async results
        try { Thread.sleep(1000); } catch (InterruptedException e) {}
    }
}