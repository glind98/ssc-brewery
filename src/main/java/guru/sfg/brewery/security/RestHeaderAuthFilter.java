package guru.sfg.brewery.security;

import javax.servlet.http.HttpServletRequest;
import org.springframework.security.web.util.matcher.RequestMatcher;

public class RestHeaderAuthFilter extends AbstractRestAuthFilter
{
    public RestHeaderAuthFilter(RequestMatcher requiresAuthenticationRequestMatcher)
    {
        super(requiresAuthenticationRequestMatcher);
    }
    
    protected String getUsername(HttpServletRequest request)
    {
        return request.getHeader("Api-Key");
    }
    
    protected String getPassword(HttpServletRequest request)
    {
        return request.getHeader("Api-Secret");
    }    
}