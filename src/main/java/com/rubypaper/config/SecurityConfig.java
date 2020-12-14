package com.rubypaper.config;

//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.context.annotation.Bean;
//import org.springframework.security.crypto.factory.PasswordEncoderFactories;
//import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@EnableWebSecurity  //시큐리티 설정 파일임을 의미
public class SecurityConfig extends WebSecurityConfigurerAdapter {
//	@Autowired
//	private BoardUserDetailsService boardUserDetailsService;

	@Override
	protected void configure(HttpSecurity security) throws Exception {
		security.authorizeRequests().antMatchers("/").permitAll();
		security.authorizeRequests().antMatchers("/member/**").authenticated();
		security.authorizeRequests().antMatchers("/manager/**").hasRole("MANAGER");
		security.authorizeRequests().antMatchers("/admin/**").hasRole("ADMIN");

		security.csrf().disable();
		
		
//		security.formLogin().loginPage("/login").defaultSuccessUrl("/loginSuccess", true);
//		security.exceptionHandling().accessDeniedPage("/accessDenied");
//		security.logout().invalidateHttpSession(true).logoutSuccessUrl("/login");
//
//		security.userDetailsService(boardUserDetailsService);

	}
	
//	@Bean 
//	public PasswordEncoder passwordEncoder() {
//		return PasswordEncoderFactories.createDelegatingPasswordEncoder();
//	}

}
