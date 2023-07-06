/*
 * Copyright 2013-2023 the original author or authors.
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

package org.springframework.cloud.gateway.server.mvc.filter;

import java.lang.reflect.Method;
import java.net.URI;
import java.util.Arrays;
import java.util.Collection;
import java.util.Map;
import java.util.regex.Pattern;

import org.springframework.cloud.gateway.server.mvc.common.MvcUtils;
import org.springframework.cloud.gateway.server.mvc.common.Shortcut;
import org.springframework.cloud.gateway.server.mvc.handler.GatewayServerResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.util.StringUtils;
import org.springframework.web.servlet.function.HandlerFilterFunction;
import org.springframework.web.servlet.function.ServerRequest;
import org.springframework.web.servlet.function.ServerResponse;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriTemplate;

public interface FilterFunctions {

	@Shortcut
	static HandlerFilterFunction<ServerResponse, ServerResponse> addRequestHeader(String name, String... values) {
		return (request, next) -> {
			String[] expandedValues = MvcUtils.expandMultiple(request, values);
			ServerRequest modified = ServerRequest.from(request).header(name, expandedValues).build();
			return next.handle(modified);
		};
	}

	@Shortcut
	static HandlerFilterFunction<ServerResponse, ServerResponse> addRequestParameter(String name, String... values) {
		return (request, next) -> {
			String[] expandedValues = MvcUtils.expandMultiple(request, values);
			ServerRequest modified = ServerRequest.from(request).param(name, expandedValues).build();
			return next.handle(modified);
		};
	}

	@Shortcut
	static HandlerFilterFunction<ServerResponse, ServerResponse> addResponseHeader(String name, String... values) {
		return (request, next) -> {
			ServerResponse response = next.handle(request);
			if (response instanceof GatewayServerResponse) {
				GatewayServerResponse res = (GatewayServerResponse) response;
				String[] expandedValues = MvcUtils.expandMultiple(request, values);
				res.headers().addAll(name, Arrays.asList(expandedValues));
			}
			return response;
		};
	}

	@Shortcut
	static HandlerFilterFunction<ServerResponse, ServerResponse> prefixPath(String prefix) {
		final UriTemplate uriTemplate = new UriTemplate(prefix);

		return (request, next) -> {
			Map<String, Object> uriVariables = MvcUtils.getUriTemplateVariables(request);
			URI uri = uriTemplate.expand(uriVariables);

			String newPath = uri.getRawPath() + request.uri().getRawPath();

			URI prefixedUri = UriComponentsBuilder.fromUri(request.uri()).replacePath(newPath).build().toUri();
			ServerRequest modified = ServerRequest.from(request).uri(prefixedUri).build();
			return next.handle(modified);
		};
	}

	@Shortcut
	static HandlerFilterFunction<ServerResponse, ServerResponse> rewritePath(String regexp, String replacement) {
		String normalizedReplacement = replacement.replace("$\\", "$");
		Pattern pattern = Pattern.compile(regexp);
		return (request, next) -> {
			// TODO: original request url
			String path = request.uri().getRawPath();
			String newPath = pattern.matcher(path).replaceAll(normalizedReplacement);

			URI rewrittenUri = UriComponentsBuilder.fromUri(request.uri()).replacePath(newPath).build().toUri();

			ServerRequest modified = ServerRequest.from(request).uri(rewrittenUri).build();

			MvcUtils.setRequestUrl(modified, modified.uri());

			return next.handle(modified);
		};
	}

	@Shortcut
	static HandlerFilterFunction<ServerResponse, ServerResponse> setPath(String path) {
		UriTemplate uriTemplate = new UriTemplate(path);

		return (request, next) -> {
			Map<String, Object> uriVariables = MvcUtils.getUriTemplateVariables(request);
			URI uri = uriTemplate.expand(uriVariables);
			String newPath = uri.getRawPath();

			URI prefixedUri = UriComponentsBuilder.fromUri(request.uri()).replacePath(newPath).build().toUri();
			ServerRequest modified = ServerRequest.from(request).uri(prefixedUri).build();
			return next.handle(modified);
		};
	}

	static HandlerFilterFunction<ServerResponse, ServerResponse> stripPrefix() {
		return stripPrefix(1);
	}

	@Shortcut
	static HandlerFilterFunction<ServerResponse, ServerResponse> stripPrefix(int parts) {
		return (request, next) -> {
			// TODO: gateway url attributes
			String path = request.uri().getRawPath();
			// TODO: begin duplicate code from StripPrefixGatewayFilterFactory
			String[] originalParts = StringUtils.tokenizeToStringArray(path, "/");

			// all new paths start with /
			StringBuilder newPath = new StringBuilder("/");
			for (int i = 0; i < originalParts.length; i++) {
				if (i >= parts) {
					// only append slash if this is the second part or greater
					if (newPath.length() > 1) {
						newPath.append('/');
					}
					newPath.append(originalParts[i]);
				}
			}
			if (newPath.length() > 1 && path.endsWith("/")) {
				newPath.append('/');
			}
			// TODO: end duplicate code from StripPrefixGatewayFilterFactory

			URI prefixedUri = UriComponentsBuilder.fromUri(request.uri()).replacePath(newPath.toString()).build()
					.toUri();
			ServerRequest modified = ServerRequest.from(request).uri(prefixedUri).build();
			return next.handle(modified);
		};
	}

	// TODO: current discovery only goes by method name
	// so last one wins, so put int first for now
	static HandlerFilterFunction<ServerResponse, ServerResponse> setStatus(int statusCode) {
		return setStatus(HttpStatus.valueOf(statusCode));
	}

	// TODO: handle int or string for config
	static HandlerFilterFunction<ServerResponse, ServerResponse> setStatus(HttpStatusCode statusCode) {
		return (request, next) -> {
			ServerResponse response = next.handle(request);
			if (response instanceof GatewayServerResponse) {
				GatewayServerResponse res = (GatewayServerResponse) response;
				res.setStatusCode(statusCode);
			}
			return response;
		};
	}

	class FilterSupplier implements org.springframework.cloud.gateway.server.mvc.filter.FilterSupplier {

		@Override
		public Collection<Method> get() {
			return Arrays.asList(FilterFunctions.class.getMethods());
		}

	}

}
