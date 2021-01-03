package guru.sfg.brewery.web.controllers;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
// import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.boot.test.context.SpringBootTest;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.anonymous;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

// @WebMvcTest
@SpringBootTest
public class BeerControllerIT extends BaseIT
{
    @Test
    void initCreationForm() throws Exception{
        mockMvc.perform(get("/beers/new").with(httpBasic("user", "password")))
                .andExpect(status().isOk())
                .andExpect(view().name("beers/createBeer"))
                .andExpect(model().attributeExists("beer"));
    }
    
    @Test
    void initCreationFormWithScott() throws Exception{
        mockMvc.perform(get("/beers/new").with(httpBasic("scott", "tiger")))
                .andExpect(status().isOk())
                .andExpect(view().name("beers/createBeer"))
                .andExpect(model().attributeExists("beer"));
    }  
    
    @Test
    void initCreationFormWithSpring() throws Exception{
        mockMvc.perform(get("/beers/new").with(httpBasic("spring", "guru")))
                .andExpect(status().isOk())
                .andExpect(view().name("beers/createBeer"))
                .andExpect(model().attributeExists("beer"));
    }      
    
    // @WithMockUser("spring")
    @Test
    void findBeers() throws Exception{
        mockMvc.perform(get("/beers/find"))
                .andExpect(status().isOk())
                .andExpect(view().name("beers/findBeers"))
                .andExpect(model().attributeExists("beer"));
    }
    
    @Test
    void findBeersWithAnonymous() throws Exception
    {
        mockMvc.perform(get("/beers/find").with(anonymous()))
        .andExpect(status().isOk())
        .andExpect(view().name("beers/findBeers"))
        .andExpect(model().attributeExists("beer"));
    }     
}