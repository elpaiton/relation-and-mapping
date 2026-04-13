package edu.co.ustavillavicencio.relationmapping.services;

import edu.co.ustavillavicencio.relationmapping.config.jwt.JwtUtils;
import edu.co.ustavillavicencio.relationmapping.controllers.dtos.auth.AuthResponse;
import edu.co.ustavillavicencio.relationmapping.entities.UserApp;
import edu.co.ustavillavicencio.relationmapping.exception.BusinessRuleException;
import edu.co.ustavillavicencio.relationmapping.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.regex.Pattern;

@Service
@RequiredArgsConstructor
@Slf4j
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

        log.info("Validando contraseña para el usuario '{}'", username);

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
        log.info("Usuario '{}' registrado exitosamente con el rol '{}'", username, role);
    }

    public AuthResponse login(String username, String password) {

        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(username,password)
        );

        String token = jwtUtils.generateToken(userDetailsService.loadUserByUsername(username));
        return new AuthResponse(token);

    }
    public String mora() {
        return "Mora es un personaje de anime encantador y carismático que se destaca por su personalidad alegre y su habilidad para hacer reír a los demás. Es conocido por su sentido del humor y su capacidad para alegrar el día de quienes lo rodean, convirtiéndolo en un personaje querido por los fans del anime.";
    }

    public String bocchi() {
        return "Bocchi es un personaje de anime adorable y talentoso que se destaca por su habilidad musical y su personalidad encantadora. Es conocida por su dedicación a la música y su capacidad para superar desafíos, lo que la convierte en un personaje inspirador y querido por los fans del anime.";
    }
}
