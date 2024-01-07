package spring.security.cognito.presentation.user;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/v1")
public class UserController {

  @GetMapping("/users")
  public String getUsers() {
    return "Hello World from Authenticated User";
  }
}
