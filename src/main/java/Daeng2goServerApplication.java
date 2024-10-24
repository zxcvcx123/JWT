package org.daeng2go.daeng2go_server;

import org.daeng2go.daeng2go_server.common.config.ChatGPTConfig;
import org.daeng2go.daeng2go_server.common.config.JwtPropertiesConfig;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.scheduling.annotation.EnableScheduling;

@EnableScheduling
@SpringBootApplication
@EnableConfigurationProperties({ChatGPTConfig.class, JwtPropertiesConfig.class})
public class Daeng2goServerApplication {
    public static void main(String[] args) {
        SpringApplication.run(Daeng2goServerApplication.class, args);
    }

}
