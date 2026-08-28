package com.augustopugliano.cypher;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;

@SpringBootApplication
@EnableAsync
public class CypherApplication {

	public static void main(String[] args) {
		SpringApplication.run(CypherApplication.class, args);
	}

}
