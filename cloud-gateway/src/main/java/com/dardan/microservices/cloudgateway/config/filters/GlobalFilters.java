package com.dardan.microservices.cloudgateway.config.filters;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;


@Component
public class GlobalFilters implements GlobalFilter {


    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

        return chain.filter(exchange).then(Mono.fromRunnable(() -> {
            exchange.getResponse().getCookies().add("Token", ResponseCookie.from("dardanToken", "TOKEN").build());
            exchange.getResponse().getHeaders().add("dardan-Header", exchange.getRequest().getHeaders().getFirst("appCallerName"));
        }));


    }
}
