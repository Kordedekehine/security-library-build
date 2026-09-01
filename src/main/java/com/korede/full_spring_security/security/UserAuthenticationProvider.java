package com.korede.full_spring_security.security;

import org.springframework.security.core.userdetails.UserDetails;

public interface UserAuthenticationProvider {

    UserDetails loadUser(String username);
}
