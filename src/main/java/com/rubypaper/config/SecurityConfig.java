package com.rubypaper.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
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
		security.authorizeRequests().antMatchers("/member/**").authenticated(); // 로그인 되면 접근 가능한 페이지
		security.authorizeRequests().antMatchers("/manager/**").hasRole("MANAGER");
		security.authorizeRequests().antMatchers("/admin/**").hasRole("ADMIN");

		security.csrf().disable();
		//security.formLogin(); // 허용되지 않은 주소 접근시 디폴트 로그인 화면 보임
		security.formLogin().loginPage("/login").defaultSuccessUrl("/loginSuccess", true); //사용자가 만든 로그인 보임
		security.exceptionHandling().accessDeniedPage("/accessDenied");  //접근 권한 없는 페이지로 이동할 경우 이동
		security.logout().invalidateHttpSession(true).logoutSuccessUrl("/login"); //로그아웃시 이동하는 주소
//
//		security.userDetailsService(boardUserDetailsService);

	}
	
//	@Bean 
//	public PasswordEncoder passwordEncoder() {
//		return PasswordEncoderFactories.createDelegatingPasswordEncoder();
//	}
	
	//메모리 임시 로그인 -  콘솔에 찍힌 패스워드 말고 로그인 가능
	@Autowired
	public void authenticate(AuthenticationManagerBuilder auth) throws Exception{
		auth.inMemoryAuthentication()
		.withUser("manager")
		.password("{noop}manager123")
		.roles("MANAGER");
		
		auth.inMemoryAuthentication()
		.withUser("admin")
		.password("{noop}admin123")
		.roles("ADMIN");
	}

}
