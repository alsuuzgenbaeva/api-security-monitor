package com.apisecurity.monitor.security;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.assertj.core.api.Assertions.assertThat;

class SecurityConfigurationTest {

    @Test
    void createsBcryptProtectedLocalAdministrator() {
        MonitoringSecurityProperties properties = new MonitoringSecurityProperties();
        properties.setAdminUsername("local-admin");
        properties.setAdminPassword("environment-supplied-password");
        SecurityConfiguration configuration = new SecurityConfiguration();
        PasswordEncoder encoder = configuration.passwordEncoder();

        UserDetailsService userDetailsService = configuration.userDetailsService(properties, encoder);
        UserDetails administrator = userDetailsService.loadUserByUsername("local-admin");

        assertThat(administrator.getPassword()).startsWith("$2").isNotEqualTo(properties.getAdminPassword());
        assertThat(encoder.matches(properties.getAdminPassword(), administrator.getPassword())).isTrue();
        assertThat(administrator.getAuthorities()).extracting("authority").containsExactly("ROLE_ADMIN");
    }
}
