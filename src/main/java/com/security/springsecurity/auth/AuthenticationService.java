package com.security.springsecurity.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.security.springsecurity.config.JwtService;
import com.security.springsecurity.token.Token;
import com.security.springsecurity.token.TokenRepository;
import com.security.springsecurity.token.TokenType;
import com.security.springsecurity.user.User;
import com.security.springsecurity.user.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
  private final UserRepository repository;
  private final TokenRepository tokenRepository;
  private final PasswordEncoder passwordEncoder;
  private final JwtService jwtService;
  private final AuthenticationManager authenticationManager;

  public AuthenticationResponse register(RegisterRequest request) {
    var user = User.builder()
        .firstname(request.getFirstname())
        .lastname(request.getLastname())
        .email(request.getEmail())
        .password(passwordEncoder.encode(request.getPassword()))
        .role(request.getRole())
        .build();
    var savedUser = repository.save(user);
    var jwtToken = jwtService.generateToken(user);
    var refreshToken = jwtService.generateRefreshToken(user); // genrate refresh token: yeni bir token oluşturulur
    saveUserToken(savedUser, jwtToken); // save user token: kullanıcıya ait token kaydedilir
    return AuthenticationResponse.builder() // return authentication response: kullanıcıya ait token ve refresh token döndürülür
        .accessToken(jwtToken)
            .refreshToken(refreshToken)
        .build();
  }

  public AuthenticationResponse authenticate(AuthenticationRequest request) { // authenticate: kullanıcı doğrulanır
    authenticationManager.authenticate(
        new UsernamePasswordAuthenticationToken( // kullanıcı adı ve şifre ile token oluşturulur
            request.getEmail(),
            request.getPassword()
        )
    );
    var user = repository.findByEmail(request.getEmail()) // kullanıcı adı ile kullanıcı bulunur
        .orElseThrow();
    var jwtToken = jwtService.generateToken(user);
    var refreshToken = jwtService.generateRefreshToken(user);
    revokeAllUserTokens(user); // kullanıcıya ait tüm tokenler iptal edilir
    saveUserToken(user, jwtToken); // kullanıcıya ait token kaydedilir
    return AuthenticationResponse.builder() // kullanıcıya ait token ve refresh token döndürülür
        .accessToken(jwtToken)
            .refreshToken(refreshToken)
        .build();
  }

  private void saveUserToken(User user, String jwtToken) {
    var token = Token.builder()
        .user(user)
        .token(jwtToken)
        .tokenType(TokenType.BEARER) // token type: token türü belirlenir başka da var
        .expired(false) // expired: tokenin süresi dolmuş mu
        .revoked(false) // revoked: token iptal edilmiş mi
        .build();
    tokenRepository.save(token); // token kaydedilir
  }

  private void revokeAllUserTokens(User user) { // kullanıcıya ait tüm tokenler iptal edilir
    var validUserTokens = tokenRepository.findAllValidTokenByUser(user.getId()); // kullanıcıya ait tüm tokenler bulunur
    if (validUserTokens.isEmpty()) // eğer token yoksa
      return;
    validUserTokens.forEach(token -> { // tokenlerin süresi dolmuş ve iptal edilmiş olarak işaretlenir
      token.setExpired(true);
      token.setRevoked(true);
    });
    tokenRepository.saveAll(validUserTokens); // tokenler kaydedilir
  }

  public void refreshToken(
          HttpServletRequest request,
          HttpServletResponse response
  ) throws IOException {
    final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION); // authorization header: requestten authorization header alınır
    final String refreshToken;
    final String userEmail;
    if (authHeader == null ||!authHeader.startsWith("Bearer ")) { // eğer authorization header yoksa veya başlangıcı Bearer değilse
      return;
    }
    refreshToken = authHeader.substring(7); // refresh token: authorization headerdan refresh token alınır
    userEmail = jwtService.extractUsername(refreshToken); // user email: refresh tokendan kullanıcı adı alınır
    if (userEmail != null) {
      var user = this.repository.findByEmail(userEmail) // kullanıcı adı ile kullanıcı bulunur
              .orElseThrow();
      if (jwtService.isTokenValid(refreshToken, user)) { // eğer token süresi geçmemişse
        var accessToken = jwtService.generateToken(user); //  yeni bir token oluşturulur
        revokeAllUserTokens(user); // kullanıcıya ait tüm tokenler iptal edilir
        saveUserToken(user, accessToken);
        var authResponse = AuthenticationResponse.builder() // kullanıcıya ait token ve refresh token döndürülür
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
        new ObjectMapper().writeValue(response.getOutputStream(), authResponse); // response: response body e token ve refresh token yazılır
      }
    }
  }
}
