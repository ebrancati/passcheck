import io.github.ebrancati.password.PasswordValidator;
import java.util.List;

public class BasicExample {

    public static void main(String[] args) {

        boolean isValid = new PasswordValidator()
                                .minLength(6)
                                .requireDigits()
                                .isValid("psw456");

        System.out.println("Password valid: " + isValid);
    }
}