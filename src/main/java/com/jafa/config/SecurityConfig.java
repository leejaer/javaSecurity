package com.jafa.config;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;

import com.jafa.service.CustomUserDetailService;

@Configuration
@EnableWebSecurity
@ComponentScan("com.jafa.security")
@EnableGlobalMethodSecurity(prePostEnabled = true,securedEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	AccessDeniedHandler accessDeniedHandler;
	
	@Autowired
	AuthenticationFailureHandler authenticationFailureHandler;

	@Autowired
	AuthenticationSuccessHandler authenticationSuccessHandler;
	
	@Autowired
	LogoutSuccessHandler logoutSuccessHandler;
	
	@Autowired
	DataSource dataSource;
	@Bean
	public UserDetailsService userDetailsService() {
		return new CustomUserDetailService();
	}
	
//	컴포넌트로 자동 등록가능
//	@Bean 
//	public AccessDeniedHandler accessDeniedHandler() {
//		return new MemberAccessDeniedHanlder();
//	};
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		/*
		 * http.authorizeRequests() .antMatchers("/member/all").access("permitAll")
		 * .antMatchers("/member/member").access("hasRole('ROLE_MEMBER')")
		 * .antMatchers("/member/myPage")
		 * .access("hasAnyRole('ROLE_REGULAR_MEMBER','ROLE_ASSOCIATE_MEMBER')")
		 * .antMatchers("/member/admin").access("hasRole('ROLE_ADMIN')");
		 */
		http
		.exceptionHandling()
		.accessDeniedHandler(accessDeniedHandler)
		.and()
		.formLogin()
		.loginPage("/member/login")
		.loginProcessingUrl("/member/login")
		.usernameParameter("loginId")
		.passwordParameter("loginPwd")
		.failureHandler(authenticationFailureHandler)
		.successHandler(authenticationSuccessHandler)
		.and()
		.logout()
		.invalidateHttpSession(true)
		.logoutUrl("/member/logout")
		.logoutSuccessHandler(logoutSuccessHandler)
		.logoutSuccessUrl("/")
		.deleteCookies("remember-me","JSESSION_ID")
		.and()
		.rememberMe()
		.key("lee")
		.tokenRepository(persistentTokenRepository())
		.rememberMeParameter("remember-me")
		.tokenValiditySeconds(99999);
		;
		
		/* 표현식
		 * http.authorizeRequests() 
			.antMatchers("/member/all").access("permitAll")
			.antMatchers("/member/member")
				.access("hasAnyRole('ROLE_REGULAR_MEMBER','ROLE_ASSOCIATE_MEMBER')")
			.antMatchers("/member/admin")
				.access("hasAnyRole('ROLE_ADMIN','ROLE_SUB_ADMIN')");
		*/
		
	}
	
	@Bean
	public PersistentTokenRepository persistentTokenRepository() {
		JdbcTokenRepositoryImpl jdbcTokenRepository =  new JdbcTokenRepositoryImpl();
		jdbcTokenRepository.setDataSource(dataSource);
		return jdbcTokenRepository;
	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(userDetailsService())
		.passwordEncoder(passwordEncoder());
	}
	
	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
}
