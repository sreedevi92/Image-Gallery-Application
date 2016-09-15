package edu.cmu.iccb;

import java.security.Principal;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.Filter;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.filter.CompositeFilter;




@SpringBootApplication
@EnableOAuth2Client
@RestController
public class Application extends WebSecurityConfigurerAdapter {
	//FUUUUUUUUUUUUU
	  @Autowired
	  OAuth2ClientContext oauth2ClientContext;
	
	  @RequestMapping({"/login", "/images"})
	  public Principal user(Principal principal) {
		  System.out.println(principal);
	    return principal;
	  }
	  
	  @Override
	  protected void configure(HttpSecurity http) throws Exception {
	    http
	      .antMatcher("/**")
	      .authorizeRequests()
	        .antMatchers("/", "/login**", "/webjars/**", "/css**", "/js**", "/fonts**", "/github/success**")
	        .permitAll()
	      .anyRequest()
	        .authenticated()
	        .and().logout().logoutSuccessUrl("/").permitAll()
	        .and().csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
	        .and().addFilterBefore(ssoFilter(), BasicAuthenticationFilter.class);

	  }

	  private Filter ssoFilter() {

		  CompositeFilter filter = new CompositeFilter();
		  List<Filter> filters = new ArrayList<>();

		  OAuth2ClientAuthenticationProcessingFilter facebookFilter = new OAuth2ClientAuthenticationProcessingFilter("/login/facebook");
		  OAuth2RestTemplate facebookTemplate = new OAuth2RestTemplate(facebook(), oauth2ClientContext);
		  facebookFilter.setRestTemplate(facebookTemplate);
		  facebookFilter.setTokenServices(new UserInfoTokenServices(facebookResource().getUserInfoUri(), facebook().getClientId()));
		  filters.add(facebookFilter);

		  OAuth2ClientAuthenticationProcessingFilter githubFilter = new OAuth2ClientAuthenticationProcessingFilter("/login/github");
		  OAuth2RestTemplate githubTemplate = new OAuth2RestTemplate(github(), oauth2ClientContext);
		  githubFilter.setRestTemplate(githubTemplate);
		  githubFilter.setTokenServices(new UserInfoTokenServices(githubResource().getUserInfoUri(), github().getClientId()));
		  filters.add(githubFilter);

		  filter.setFilters(filters);
		  return filter;

		}
	  
	  @Bean
	  @ConfigurationProperties("facebook.client")
	  public AuthorizationCodeResourceDetails facebook() {
	    return new AuthorizationCodeResourceDetails();
	  }
	  
	  @Bean
	  @ConfigurationProperties("facebook.resource")
	  public ResourceServerProperties facebookResource() {
	    return new ResourceServerProperties();
	  }
	  
	  @Bean
	  @ConfigurationProperties("github.client")
	  public AuthorizationCodeResourceDetails github() {
	  	return new AuthorizationCodeResourceDetails();
	  }

	  @Bean
	  @ConfigurationProperties("github.resource")
	  public ResourceServerProperties githubResource() {
	  	return new ResourceServerProperties();
	  }
	  
	  @Bean
	  public FilterRegistrationBean oauth2ClientFilterRegistration(
	      OAuth2ClientContextFilter filter) {
	    FilterRegistrationBean registration = new FilterRegistrationBean();
	    registration.setFilter(filter);
	    registration.setOrder(-100);
	    return registration;
	  }
	  

    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
    


}
