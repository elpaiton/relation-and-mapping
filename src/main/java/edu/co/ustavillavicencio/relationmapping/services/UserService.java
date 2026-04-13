package edu.co.ustavillavicencio.relationmapping.services;

import edu.co.ustavillavicencio.relationmapping.config.jwt.JwtUtils;
import edu.co.ustavillavicencio.relationmapping.controllers.dtos.auth.AuthResponse;
import edu.co.ustavillavicencio.relationmapping.entities.UserApp;
import edu.co.ustavillavicencio.relationmapping.exception.BusinessRuleException;
import edu.co.ustavillavicencio.relationmapping.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.regex.Pattern;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final UserDetailsService userDetailsService;
    private final JwtUtils jwtUtils;
    private final AuthenticationManager authenticationManager;

    public void signup(String username, String password, String role) {

        boolean passwordValid = Pattern.compile("^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{8,}$")
                .matcher(password)
                .find();


        if (userRepository.findByUsername(username).isPresent()) {
            throw new BusinessRuleException("El usuario ya existe");
        }

        if (!passwordValid) {
            throw new BusinessRuleException("La contraseña no cumple con los requisitos de seguridad");
        }

        if (userRepository.countByRole("ADMIN") >= 1 && role.equals("ADMIN")) {
            throw new BusinessRuleException("Ya existe un administrador registrado");
        }

        if(!role.equals("USER") && !role.equals("ADMIN")) {
            throw new BusinessRuleException("Rol no válido");
        }



        UserApp user = new UserApp();
        user.setUsername(username);
        user.setPassword(passwordEncoder.encode(password));
        user.setRole(role);

        userRepository.save(user);
    }

    public AuthResponse login(String username, String password) {

        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(username,password)
        );

        String token = jwtUtils.generateToken(userDetailsService.loadUserByUsername(username));
        return new AuthResponse(token);
    }

    public String hello() {
        return "Hello, authenticated user!";
    }
}
