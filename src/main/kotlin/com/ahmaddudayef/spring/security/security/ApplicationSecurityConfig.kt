package com.ahmaddudayef.spring.security.security

import com.ahmaddudayef.spring.security.auth.ApplicationUserService
import com.ahmaddudayef.spring.security.jwt.JwtConfig
import com.ahmaddudayef.spring.security.jwt.JwtTokenVerifier
import com.ahmaddudayef.spring.security.jwt.JwtUsernameAndPasswordAuthenticationFilter
import com.ahmaddudayef.spring.security.security.ApplicationUserRole.STUDENT
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.dao.DaoAuthenticationProvider
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.util.matcher.AntPathRequestMatcher
import java.util.concurrent.TimeUnit
import javax.crypto.SecretKey


@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
class ApplicationSecurityConfig @Autowired constructor(
    private val passwordEncoder: PasswordEncoder,
    private val applicationUserService: ApplicationUserService,
    private val authenticationConfiguration: AuthenticationConfiguration,
    private val secretKey: SecretKey,
    private val jwtConfig: JwtConfig
) {

    @Bean
    fun authenticationManager(authenticationConfiguration: AuthenticationConfiguration): AuthenticationManager {
        return authenticationConfiguration.authenticationManager
    }

    @Bean
    @Throws(Exception::class)
    fun filterChain(http: HttpSecurity): SecurityFilterChain {
        http
//            .csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
//            .and()
            .csrf().disable() // Use CSRF only if processed by browser, disabled it if just for non-browser client
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
            .addFilter(JwtUsernameAndPasswordAuthenticationFilter(authenticationManager(authenticationConfiguration), jwtConfig, secretKey))
            .addFilterAfter(JwtTokenVerifier(jwtConfig, secretKey), JwtUsernameAndPasswordAuthenticationFilter::class.java)
            .authorizeRequests()
            .antMatchers("/", "index", "/css/*", "/js/*").permitAll()
            .antMatchers("/api/**").hasRole(STUDENT.name)
//            .antMatchers(HttpMethod.DELETE, "/management/api/**").hasAuthority(COURSE_WRITE.permission)
//            .antMatchers(HttpMethod.POST, "/management/api/**").hasAuthority(COURSE_WRITE.permission)
//            .antMatchers(HttpMethod.PUT, "/management/api/**").hasAuthority(COURSE_WRITE.permission)
//            .antMatchers("/management/api/**").hasAnyRole(ADMIN.name, ADMINTRAINEE.name)
            .anyRequest()
            .authenticated()
            .and()
//            .httpBasic() // basic auth

//            .formLogin() // form login
//                .loginPage("/login")
//                .permitAll()
//                .defaultSuccessUrl("/courses", true)
//                .passwordParameter("password")
//                .usernameParameter("username")
//            .and()
//            .rememberMe()
//                .tokenValiditySeconds(TimeUnit.DAYS.toSeconds(21).toInt())
//                .key("somethingverysecured")
//                .rememberMeParameter("remember-me")
//            .and()
//            .logout()
//                .logoutUrl("/logout")
//                .logoutRequestMatcher(AntPathRequestMatcher("/logout", "GET")) // csrf enabled it's must be deleted
//                .clearAuthentication(true)
//                .invalidateHttpSession(true)
//                .deleteCookies("JSESSIONID", "remember-me")
//                .logoutSuccessUrl("/login")
        return http.build()
    }

//    @Bean
//    fun userDetailsService(): UserDetailsService {
//        val narutoUser: UserDetails = User.builder()
//            .username("naruto")
//            .password(passwordEncoder.encode("password"))
////            .roles(STUDENT.name) // ROLE_STUDENT
//            .authorities(STUDENT.grantedAuthorities)
//            .build()
//
//        val sakuraUser: UserDetails = User.builder()
//            .username("sakura")
//            .password(passwordEncoder.encode("password"))
////            .roles(STUDENT.name) // ROLE_STUDENT
//            .authorities(STUDENT.grantedAuthorities)
//            .build()
//
//        val sasukeUser: UserDetails = User.builder()
//            .username("sasuke")
//            .password(passwordEncoder.encode("password123"))
////            .roles(ADMINTRAINEE.name) // ROLE_ADMINTRAINEE
//            .authorities(ADMINTRAINEE.grantedAuthorities)
//            .build()
//
//        val kakashiUser: UserDetails = User.builder()
//            .username("kakashi")
//            .password(passwordEncoder.encode("password123"))
////            .roles(ADMIN.name) // ROLE_ADMIN
//            .authorities(ADMIN.grantedAuthorities)
//            .build()
//
//        return InMemoryUserDetailsManager(
//            narutoUser,
//            sakuraUser,
//            sasukeUser,
//            kakashiUser
//        )
//    }

    @Throws(Exception::class)
    fun configure(auth: AuthenticationManagerBuilder) {
        auth.authenticationProvider(daoAuthenticationProvider())
    }


    @Bean
    fun daoAuthenticationProvider(): DaoAuthenticationProvider {
        val provider = DaoAuthenticationProvider()
        provider.setPasswordEncoder(passwordEncoder)
        provider.setUserDetailsService(applicationUserService)
        return provider
    }


}