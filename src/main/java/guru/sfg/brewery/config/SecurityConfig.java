package guru.sfg.brewery.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.LdapShaPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.StandardPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import guru.sfg.brewery.security.RestHeaderAuthFilter;
import guru.sfg.brewery.security.RestUrlAuthFilter;
import guru.sfg.brewery.security.SFGPasswordEncoderFactories;

@Configuration
@EnableWebSecurity
// @EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter
{
    public RestHeaderAuthFilter restHeaderAuthFilter(AuthenticationManager authenticationManager)
    {
        RestHeaderAuthFilter filter = new RestHeaderAuthFilter(new AntPathRequestMatcher("/api/**"));
        filter.setAuthenticationManager(authenticationManager);
        return filter;        
    }
    
    public RestUrlAuthFilter restUrlAuthFilter(AuthenticationManager authenticationManager)
    {
        RestUrlAuthFilter filter = new RestUrlAuthFilter(new AntPathRequestMatcher("/api/**"));
        filter.setAuthenticationManager(authenticationManager);
        return filter;        
    }    
    
    @Override
    protected void configure(HttpSecurity http) throws Exception
    {
        /*
        http.addFilterBefore(restHeaderAuthFilter(authenticationManager()), 
                UsernamePasswordAuthenticationFilter.class)
        .csrf().disable();
                
        http.addFilterBefore(restUrlAuthFilter(authenticationManager()), 
                UsernamePasswordAuthenticationFilter.class);
        */
        
        http
        .authorizeRequests(authorize -> {
            authorize
                    .antMatchers("/h2-console/**").permitAll() //do not use in production!
                    .antMatchers("/", "/webjars/**", "/login", "/resources/**").permitAll()
                    .antMatchers(HttpMethod.GET, "/api/v1/beer/**")
                        .hasAnyRole("ADMIN", "CUSTOMER", "USER")
                    // .mvcMatchers(HttpMethod.DELETE, "/api/v1/beer/**").hasRole("ADMIN")
                    .mvcMatchers(HttpMethod.GET, "/api/v1/beerUpc/{upc}")
                        .hasAnyRole("ADMIN", "CUSTOMER", "USER")
                    .mvcMatchers("/brewery/breweries")
                        .hasAnyRole("ADMIN", "CUSTOMER")
                    .mvcMatchers(HttpMethod.GET, "/brewery/api/v1/breweries")
                        .hasAnyRole("ADMIN", "CUSTOMER")
                    .mvcMatchers("/beers/find", "/beers/{beerId}")
                        .hasAnyRole("ADMIN", "CUSTOMER", "USER");
        } )
        .authorizeRequests()
        .anyRequest().authenticated()
        .and()
        .formLogin().and()
        .httpBasic()
        .and().csrf().disable();
        
        // h2 console config
        http.headers().frameOptions().sameOrigin();
    }
    
    /*
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception
    {
        auth.inMemoryAuthentication()
            .withUser("spring")
            // .password("guru")
            // .password("{SSHA}dHejYxE8SfIKPXsIz7wMLaCGfyIqIIF4GOahgA==")
            // .password("0787b3e74bf422786ca3c5f8c494bc4b497917237bd483c9b4a6191e82a32cddcd5933ed750a2613")
            .password("{bcrypt}$2a$10$l5bT03sW8EyaCqotGhoFJub.cw75lVNh.aPkhQ/SWfk7T4Th/Ei7O")
            .roles("ADMIN")
            .and()
            .withUser("user")
            // .password("password")
            // .password("{SSHA}dHejYxE8SfIKPXsIz7wMLaCGfyIqIIF4GOahgA==")
            // .password("0787b3e74bf422786ca3c5f8c494bc4b497917237bd483c9b4a6191e82a32cddcd5933ed750a2613")
            // .password("$2a$10$piIXX9pgs1nnYvpLwuKO2.fM3Q/IipUoh3R47N5yt9WCdedwjAA1a")
            .password("{sha256}f51c8a445f9655394e3ac59e384706198e7e6984dab265c5c90ef53327ed88789894b3835101af71")
            .roles("USER");
        
        // auth.inMemoryAuthentication().withUser("scott").password("tiger").roles("CUSTOMER");
        // auth.inMemoryAuthentication().withUser("scott").password("{ldap}{SSHA}F+n+wGM7xByvmgVLZT8J4e+N7Qy3vj5K20Wbng==").roles("CUSTOMER");
        auth.inMemoryAuthentication().withUser("scott").password("{bcrypt15}$2a$15$Ri8vEsehP.k3bnFL4.w71.JsjFzsc0lhS7nw7RaFBBuTfaGW69m8m").roles("CUSTOMER");
    }
    */    
    
    /*
    @Override
    @Bean
    protected UserDetailsService userDetailsService()
    {
        UserDetails admin = User.withDefaultPasswordEncoder()
              .username("spring")
              .password("guru")
              .roles("ADMIN")
              .build();
        
        UserDetails user = User.withDefaultPasswordEncoder()
                .username("user")
                .password("password")
                .roles("USER")
                .build();
        
        return new InMemoryUserDetailsManager(admin, user);
    } 
    */
    
    /*
    @Bean
    public PasswordEncoder passwordEncoder()
    {
        return NoOpPasswordEncoder.getInstance();
    }
    */
    
    /*
    @Bean
    public PasswordEncoder passwordEncoder()
    {
        return new LdapShaPasswordEncoder();
    }
    */
    
    /*
    @Bean
    public PasswordEncoder passwordEncoder()
    {
        return new StandardPasswordEncoder();
    }
    */
    
    /*
    @Bean
    public PasswordEncoder passwordEncoder()
    {
        return new BCryptPasswordEncoder();
    }
    */
    
    /*
    @Bean
    public PasswordEncoder passwordEncoder()
    {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    } 
    */ 
    
    @Bean
    public PasswordEncoder passwordEncoder()
    {
        return SFGPasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
}