package com.goslogic.orion.gateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication(scanBasePackages = "com.goslogic.orion.gateway")
public class OrionApiGatewayApplication {

    public static void main(String[] args) {
        SpringApplication.run(OrionApiGatewayApplication.class, args);
    }

}
