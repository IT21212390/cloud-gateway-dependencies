/*
 * Copyright 2013-2020 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.cloud.gateway.filter.factory.rewrite;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.cloud.gateway.test.BaseWebClientTests;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.codec.ServerSentEvent;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.web.reactive.server.FluxExchangeResult;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.util.UriComponentsBuilder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;

@SpringBootTest(webEnvironment = RANDOM_PORT, properties = "spring.codec.max-in-memory-size=40")
@DirtiesContext
public class ModifyResponseBodyGatewayFilterFactoryTests extends BaseWebClientTests {

	private static final String toLarge;

	static {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < 1000; i++) {
			sb.append("to-large-");
		}
		toLarge = sb.toString();
	}

	@Test
	public void testModificationOfResponseBody() {
		URI uri = UriComponentsBuilder.fromUriString(this.baseUri + "/").build(true).toUri();

		testClient.get().uri(uri).header("Host", "www.modifyresponsebodyjava.org").accept(MediaType.APPLICATION_JSON)
				.exchange().expectBody().json("{\"value\": \"httpbin compatible home\", \"length\": 23}");
	}

	@Test
	public void shouldModifySseResponseBody() {
		URI uri = UriComponentsBuilder.fromUriString(this.baseUri + "/sse").build(true).toUri();

		FluxExchangeResult<ServerSentEvent<String>> result = testClient.get().uri(uri)
				.header("Host", "www.modifyresponsebodyssejava.org").accept(MediaType.TEXT_EVENT_STREAM).exchange()
				.expectStatus().isOk().expectHeader().contentType("text/event-stream;charset=UTF-8")
				.returnResult(new ParameterizedTypeReference<ServerSentEvent<String>>() {
				});

		StepVerifier.create(result.getResponseBody()).consumeNextWith(event -> assertThat(event.data()).isEqualTo("00"))
				.consumeNextWith(event -> assertThat(event.data()).isEqualTo("01"))
				.consumeNextWith(event -> assertThat(event.data()).isEqualTo("02"))
				.consumeNextWith(event -> assertThat(event.data()).isEqualTo("03")).expectNextCount(6).thenCancel()
				.verify(Duration.ofSeconds(5L));

	}

	@Test
	public void modifyResponeBodyToLarge() {
		testClient.post().uri("/post").header("Host", "www.modifyresponsebodyjavatoolarge.org")
				.header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
				.body(BodyInserters.fromValue(toLarge)).exchange().expectStatus()
				.isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR).expectBody().jsonPath("message")
				.isEqualTo("Exceeded limit on max bytes to buffer : 40");
	}

	@EnableAutoConfiguration
	@SpringBootConfiguration
	@Import(DefaultTestConfig.class)
	public static class TestConfig {

		@Value("${test.uri}")
		String uri;

		@Bean
		public RouteLocator testRouteLocator(RouteLocatorBuilder builder) {
			return builder.routes().route("modify_response_java_test",
					r -> r.path("/").and().host("www.modifyresponsebodyjava.org").filters(f -> f.prefixPath("/httpbin")
							.modifyResponseBody(String.class, Map.class, (webExchange, originalResponse) -> {
								Map<String, Object> modifiedResponse = new HashMap<>();
								modifiedResponse.put("value", originalResponse);
								modifiedResponse.put("length", originalResponse.length());
								return Mono.just(modifiedResponse);
							})).uri(uri))
					.route("modify_response_java_test_to_large",
							r -> r.path("/").and().host("www.modifyresponsebodyjavatoolarge.org")
									.filters(f -> f.prefixPath("/httpbin").modifyResponseBody(String.class,
											String.class, (webExchange, originalResponse) -> {
												return Mono.just(toLarge);
											}))
									.uri(uri))
					.route("modify_response_java_sse", r -> r.host("www.modifyresponsebodyssejava.org").filters(
							f -> f.modifyResponseBody(byte[].class, byte[].class, (webExchange, originalResponse) -> {
								String originalEvent = new String(originalResponse);
								String modifiedEvent = originalEvent.replace("data:", "data:0");
								return Mono.just(modifiedEvent.getBytes(StandardCharsets.UTF_8));
							})).uri(uri))
					.build();
		}

	}

}
