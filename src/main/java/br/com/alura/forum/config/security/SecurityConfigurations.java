package br.com.alura.forum.config.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;

@EnableWebSecurity // habilita o spring security// essa classe vai conter toda a minha configuração de segurança
@Configuration // por ser uma classe de configuração temos que usar essa anotação para configurar uns bins do spring

public class SecurityConfigurations extends WebSecurityConfigurerAdapter   {//essa classe tem uns métodos que iremos sobrescrever
	@Autowired
	private AuthenticacaoService authenticacaoService;
	
	//configurações de autenticações/controle de login/acesso
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(authenticacaoService).passwordEncoder(new BCryptPasswordEncoder());
	}
	//configurações de autorizações/url
	@Override
		protected void configure(HttpSecurity http) throws Exception {
			http.authorizeRequests()
			.antMatchers(HttpMethod.GET, "/topicos").permitAll() //antMatchers libera os métodos que quero passar, no caso passei o get e mais alguma coisa
			.antMatchers(HttpMethod.GET, "/topicos/*").permitAll()
			.anyRequest().authenticated()
			.and().formLogin();//geralogin
		}
	//confiurações statics/css/js/imagens
	@Override
		public void configure(WebSecurity web) throws Exception {
			
		}
	//public static void main(String[]args) {
		//System.out.println(new BCryptPasswordEncoder().encode("123456")); gera senha do bcritpon
	//}
}
