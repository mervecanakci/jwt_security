package com.security.springsecurity.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

  @Value("${application.security.jwt.secret-key}")
  private String secretKey;
  @Value("${application.security.jwt.expiration}")
  private long jwtExpiration;
  @Value("${application.security.jwt.refresh-token.expiration}")
  private long refreshExpiration;

  public String extractUsername(String token) { // jwt den gelen kullanıcı adını alıyoruz
    return extractClaim(token, Claims::getSubject);
  }

  public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) { //jwt den gelen talepleri karşılamak için kullanıyoruz
    final Claims claims = extractAllClaims(token); // token içindeki verileri parse ediyoruz
    return claimsResolver.apply(claims);
  }

  public String generateToken(UserDetails userDetails) {
    return generateToken(new HashMap<>(), userDetails);
  }

  public String generateToken(
      Map<String, Object> extraClaims,
      UserDetails userDetails
  ) {
    return buildToken(extraClaims, userDetails, jwtExpiration); // extraClaims, userDetails ve jwtExpiration alıyoruz ve buildToken methoduna gönderiyoruz çünkü token üretimi için kullanıyoruz
  }

  public String generateRefreshToken(
      UserDetails userDetails
  ) {
    return buildToken(new HashMap<>(), userDetails, refreshExpiration);
  }

  private String buildToken(
          Map<String, Object> extraClaims,
          UserDetails userDetails,
          long expiration
  ) {
    return Jwts
            .builder() // token üretimi
            .setClaims(extraClaims) // token içindeki verileri map olarak tutuyoruz
            .setSubject(userDetails.getUsername()) // token içindeki kullanıcı adı
            .setIssuedAt(new Date(System.currentTimeMillis())) // token üretim tarihi
            .setExpiration(new Date(System.currentTimeMillis() + expiration)) // token süresi claimsten expiration alıyorduk ya burada kendimiz belirliyoruz 1 gün verdin
            .signWith(getSignInKey(), SignatureAlgorithm.HS256) // token imzalama, secret key ile şifreliyoruz
            .compact();
  }

  public boolean isTokenValid(String token, UserDetails userDetails) { //isTokenValid methodu ile token süresi geçmemişse ve kullanıcı adı eşitse true döndürüyoruz
    final String username = extractUsername(token); // jwt den gelen kullanıcı adını alıyoruz
    return (username.equals(userDetails.getUsername())) && !isTokenExpired(token); // kullanıcı adı eşitse ve token süresi geçmemişse
  }

  private boolean isTokenExpired(String token) { // token süresi geçmemişse
    return extractExpiration(token).before(new Date()); //getExpiration: zamanı dolmuşsa true dolmamışsa false
  }

  private Date extractExpiration(String token) { //extractExpiration methodu ile token süresini alıyoruz
    return extractClaim(token, Claims::getExpiration); //Claims::getExpiration: token süresini alıyoruz
  }

  private Claims extractAllClaims(String token) { // extractAllClaims methodu ile token içindeki verileri alıyoruz ve parse ediyoruz
    return Jwts
        .parserBuilder()
        .setSigningKey(getSignInKey()) // token imzalama, secret key ile şifreliyoruz
        .build() //build: token ı oluşturuyoruz / nesne
        .parseClaimsJws(token) //parseClaimsJws: token içindeki verileri parse ediyoruz
        .getBody(); //getBody: token içindeki verileri alıyoruz
  }

  private Key getSignInKey() { // getSignInKey methodu ile secret key i alıyoruz
    byte[] keyBytes = Decoders.BASE64.decode(secretKey); // secret key i base64 formatından çıkarıyoruz
    return Keys.hmacShaKeyFor(keyBytes); // hmacShaKeyFor: secret key i alıyoruz
  }
}
