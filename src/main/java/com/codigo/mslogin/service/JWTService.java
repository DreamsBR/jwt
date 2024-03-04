package com.codigo.mslogin.service;

import com.codigo.mslogin.service.impl.JWTServiceImpl;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.function.Function;

@Service
public class JWTService implements JWTServiceImpl {

    public String generarToken(UserDetails userDetails){

        return Jwts.builder().setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 120000))
                .signWith(getSingKey(), SignatureAlgorithm.HS256)
                .compact();
    }
    public String extracUsername(String token){
        return extractClaims(token, Claims::getSubject);
    }

    private <T> T extractClaims(String token, Function<Claims, T> claimsResolver){
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token){
        return Jwts.parserBuilder().setSigningKey(getSingKey()).build().parseClaimsJws(token).getBody();
    }

    private Key getSingKey(){
        byte[] key = Decoders.BASE64.decode("85732b878c0f544da4a863804775ef3914e8ccb82b08820a278302c5b826e291");
        return Keys.hmacShaKeyFor(key);
    }

    public boolean validToken(String token, UserDetails userDetails){
        final String username= extracUsername(token);
        return (username.equals(userDetails.getUsername()) && !istokenExpired(token));
    }

    private boolean istokenExpired(String token){
        return extractClaims(token, Claims::getExpiration).before(new Date());
    }

}
