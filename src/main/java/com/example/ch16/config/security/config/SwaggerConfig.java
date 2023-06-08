package com.example.ch16.config.security.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import static org.springframework.security.config.Elements.JWT;

@Configuration
public class SwaggerConfig {
    @Bean
    public OpenAPI openAPI(){
        Components components = new Components();
        components.addSecuritySchemes(JWT, getJwtSecuritySchemes());
        SecurityRequirement securityRequirement = new SecurityRequirement().addList(JWT);
        Info info = new Info().version("v1.0.0").
                title("CH16 API").description("Spring JPA Project");
        return new OpenAPI()
                .info(info)
                .components(components)
                .addSecurityItem(securityRequirement);
    }
    private SecurityScheme getJwtSecuritySchemes(){
        return new SecurityScheme()
                .type(SecurityScheme.Type.APIKEY)
                .in(SecurityScheme.In.HEADER).name("X-AUTH-TOKEN");
    }
}