package com.security.springsecurity.config;


import com.security.springsecurity.token.TokenRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;
    private final TokenRepository tokenRepository;

    @Override
    protected void doFilterInternal( //  doFilterInternal methodu ile istemci tarafından gelen değerleri geri gönderiyoruz
                                     @NonNull HttpServletRequest request,  // request ve response u alıyoruz
                                     @NonNull HttpServletResponse response,
                                     @NonNull FilterChain filterChain
    ) throws ServletException, IOException { // ServletException ve IOException hatalarını yakalıyoruz
        if (request.getServletPath().contains("/api/v1/auth")) { // request içindeki servletPath /api/v1/auth içeriyorsa
            filterChain.doFilter(request, response); // filterChain doFilter methodu ile request ve response u gönderiyoruz
            return;
        }
        final String authHeader = request.getHeader("Authorization"); // header içinde authorization var mı diye bakıyoruz
        final String jwt;
        final String userEmail;
        if (authHeader == null || !authHeader.startsWith("Bearer ")) { // header boş değilse ve başlangıcı Bearer ise
            filterChain.doFilter(request, response);
            return;
        }
        jwt = authHeader.substring(7); // jwt yi alıyoruz bearer dan sonrasını alıyoruz
        userEmail = jwtService.extractUsername(jwt); // jwtService içindeki extractUsername methodunu kullanarak jwt yi alıyoruz
        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) { // kullanıcı adı boş değilse ve securityContext içindeki authentication boşsa
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail); // userDetailsService içindeki loadUserByUsername methodunu kullanarak kullanıcı adını alıyoruz
            var isTokenValid = tokenRepository.findByToken(jwt) // tokenRepository içindeki findByToken methodunu kullanarak jwt yi alıyoruz
                    .map(t -> !t.isExpired() && !t.isRevoked())   // tokenRepository içindeki isExpired ve isRevoked methodlarını kullanarak token ın geçerli olup olmadığını kontrol ediyoruz
                    .orElse(false);
            if (jwtService.isTokenValid(jwt, userDetails) && isTokenValid) {  // jwtService içindeki isTokenValid methodunu kullanarak jwt yi ve userDetails ı alıyoruz
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken( // kullanıcı adı ve yetkileri ile birlikte token oluşturuyoruz
                        userDetails,
                        null,
                        userDetails.getAuthorities()  // kullanıcı yetkilerini alıyoruz
                );
                authToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request) // kullanıcı detaylarını alıyoruz
                );
                SecurityContextHolder.getContext().setAuthentication(authToken); // securityContext içindeki authentication ı authenticationToken ile set ediyoruz ve kullanıcıyı doğruluyoruz
            }
        }
        filterChain.doFilter(request, response); // filterChain ile request ve response u gönderiyoruz
    }
}
