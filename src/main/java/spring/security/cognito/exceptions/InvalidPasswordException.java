package spring.security.cognito.exceptions;

@SuppressWarnings("serial")
public class InvalidPasswordException extends ServiceException {

    public InvalidPasswordException() {
    }

    public InvalidPasswordException(String message) {
        super(message);
    }

    public InvalidPasswordException(String message, Throwable throwable) {
        super(message, throwable);
    }
}
