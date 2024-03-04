package com.codigo.mslogin.service.impl;

import com.codigo.mslogin.service.JWTService;
import org.springframework.security.core.userdetails.UserDetails;

public interface JWTServiceImpl {

    String extracUsername(String token);
    boolean validToken(String token, UserDetails userDetails);
    String generarToken(UserDetails userDetails);
}
