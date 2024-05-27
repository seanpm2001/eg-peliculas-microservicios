package org.uqbar.peliculasmicroserviceauth.security

import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpMethod
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration
import org.springframework.security.config.annotation.web.HttpSecurityDsl
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter


@Configuration
@EnableWebSecurity
class WebSecurityConfig {

    @Autowired
    lateinit var authConfiguration: AuthenticationConfiguration

    @Autowired
    lateinit var jwtAuthorizationFilter: JWTAuthorizationFilter

    @Bean
    @Throws(Exception::class)
    fun authenticationManager(): AuthenticationManager? {
        return authConfiguration.getAuthenticationManager()
    }

    @Bean
    fun filterChain(httpSecurity: HttpSecurity, authenticationManager: AuthenticationManager): SecurityFilterChain {
        return httpSecurity
            .cors { it.disable() }
            .csrf { it.disable() }
            .authorizeHttpRequests {
                it.requestMatchers(HttpMethod.POST, "/auth/login").permitAll()
                it.requestMatchers("/error").permitAll()
                // Solo permitimos que creen o eliminen usuarios los que tengan rol administrador
                it.requestMatchers(HttpMethod.POST, "/auth/user").hasAuthority("ROLE_ADMIN")
                it.requestMatchers(HttpMethod.DELETE, "/auth/user/**").hasAuthority("ROLE_ADMIN")
                    //
                    .anyRequest().authenticated()
            }
            .httpBasic(Customizer.withDefaults())
            .sessionManagement { configurer ->
                configurer.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            }
            // agregado para JWT, si comentás estas dos líneas tendrías Basic Auth
            .addFilterBefore(jwtAuthorizationFilter, UsernamePasswordAuthenticationFilter::class.java)
            // fin agregado
            .exceptionHandling(Customizer.withDefaults())
            .build()
    }
}