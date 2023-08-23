/*
 * Copyright (C) 2021+ furplag (https://github.com/furplag)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package jp.furplag.sandbox.boot.mvc;

import com.google.common.base.CaseFormat;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.Serializable;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.TimeZone;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.annotation.concurrent.Immutable;
import jp.furplag.sandbox.l10n.Localizr;
import jp.furplag.sandbox.reflect.SavageReflection;
import jp.furplag.sandbox.trebuchet.Trebuchet;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.ToString;
import lombok.Value;
import lombok.extern.slf4j.Slf4j;
import nz.net.ultraq.thymeleaf.layoutdialect.LayoutDialect;
import org.apache.commons.lang3.StringUtils;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnSingleCandidate;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.web.WebProperties;
import org.springframework.boot.autoconfigure.web.WebProperties.Resources;
import org.springframework.boot.autoconfigure.web.servlet.error.DefaultErrorViewResolver;
import org.springframework.boot.autoconfigure.web.servlet.error.ErrorViewResolver;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.boot.context.properties.bind.ConstructorBinding;
import org.springframework.boot.validation.MessageInterpolatorFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.core.MethodParameter;
import org.springframework.http.HttpStatus;
import org.springframework.ui.ModelMap;
import org.springframework.validation.DefaultMessageCodesResolver;
import org.springframework.validation.MessageCodesResolver;
import org.springframework.validation.Validator;
import org.springframework.validation.beanvalidation.LocalValidatorFactoryBean;
import org.springframework.validation.beanvalidation.LocaleContextMessageInterpolator;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.context.request.WebRequestInterceptor;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;
import org.springframework.web.servlet.AsyncHandlerInterceptor;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.i18n.CookieLocaleResolver;
import org.springframework.web.servlet.i18n.LocaleChangeInterceptor;
import org.springframework.web.servlet.i18n.SessionLocaleResolver;

public interface MvcBoilerplate {

  @Configuration(proxyBeanMethods = false)
  @ConditionalOnWebApplication
  @ConditionalOnSingleCandidate(Boilerplate.class)
  @EnableConfigurationProperties({ Properties.class, WebProperties.class })
  @Slf4j
  static final class AutoConfiguration extends Boilerplate implements WebMvcConfigurer {/* @formatter:off */
    AutoConfiguration(Properties properties, WebProperties webProperties) { super(properties, webProperties); }
    /** {@inheritDoc} */ @Override public void addArgumentResolvers(List<HandlerMethodArgumentResolver> resolvers) {
      if (properties.i18n.isEnabled()) {
        resolvers.add(new HandlerMethodArgumentResolver() {
          /** {@inheritDoc} */ @Override public Object resolveArgument(MethodParameter parameter, ModelAndViewContainer mavContainer, NativeWebRequest webRequest, WebDataBinderFactory binderFactory) throws Exception {
            return LocaleContextHolder.getTimeZone();
          }
          /** {@inheritDoc} */ @Override public boolean supportsParameter(MethodParameter parameter) { return TimeZone.class.isAssignableFrom(parameter.getParameterType()); }
        });
      }
    }
    /** {@inheritDoc} */ @Override public void addInterceptors(InterceptorRegistry registry) {
      if (properties.i18n.isEnabled()) {
        registry.addInterceptor(localeChangeInterceptor());
        registry.addInterceptor(new AsyncHandlerInterceptor() {
          /** {@inheritDoc} */ @Override public void postHandle(HttpServletRequest request, HttpServletResponse response, Object handler, ModelAndView modelAndView) throws Exception {
            if (Trebuchet.Predicates.orNot(handler, (h) -> !((HandlerMethod) h).hasMethodAnnotation(ResponseBody.class))) {
              Optional.ofNullable(modelAndView).ifPresent((mav) -> mav.getModelMap().addAttribute("timeZone", LocaleContextHolder.getTimeZone()));
            }
          }
        });
        registry.addWebRequestInterceptor(new WebRequestInterceptor() {
          /** {@inheritDoc} */ @Override public void afterCompletion(WebRequest request, Exception ex) throws Exception {}
          /** {@inheritDoc} */ @Override public void postHandle(WebRequest request, ModelMap model) throws Exception {
            Optional.ofNullable(model).ifPresent((_model) -> _model.addAttribute("timeZone", LocaleContextHolder.getTimeZone()));
          }
          /** {@inheritDoc} */ @Override public void preHandle(WebRequest request) throws Exception {}
        });
      }
    }
    /** {@inheritDoc} */ @Override public void addResourceHandlers(ResourceHandlerRegistry registry) {
      if (properties.i18n.isEnabled()) {
        registry.addResourceHandler("/").addResourceLocations("classpath:templates/", "classpath:static/", "classpath:i18n/");
        registry.addResourceHandler("/error/**").addResourceLocations("classpath:templates/error/");
        log.info("ready to use default web page resources . ");
      }
    }
    /** {@inheritDoc} */ @Bean @ConditionalOnProperty(prefix = "project.boilerplate.mvc.i18n", name = "enabled", matchIfMissing = true) @Override public ErrorViewResolver errorViewResolver(ApplicationContext applicationContext, Resources resources) { return super.errorViewResolver(applicationContext, resources); }
    /** {@inheritDoc} */ @Bean @ConditionalOnProperty(prefix = "project.boilerplate.mvc.i18n", name = "enabled", matchIfMissing = true) @Override public LocaleResolver localeResolver() { return super.localeResolver(); }
    /** {@inheritDoc} */ @Bean @Override public LayoutDialect layoutDialect() { return super.layoutDialect(); }
    /** {@inheritDoc} */ @Bean @Override public Resources resources() { return super.resources(); }
    /** {@inheritDoc} */ @PostConstruct @Override public void postConstruct() {
      super.postConstruct();
      if (properties.i18n.isEnabled()) {
        log.info("ready to enable locale changing via request and response .");
        log.info("=> ( paramName: \"{}\", locale: \"{}\", timezone: \"{}\" )", properties.i18n.paramName, properties.i18n.defaultLocale.getDisplayName(properties.i18n.defaultLocale), properties.i18n.defaultTimeZone.getDisplayName(properties.i18n.defaultLocale));
      }
    }

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnSingleCandidate(ValidationMessageAutoConfiguration.class)
    @ConditionalOnClass(name = { "jakarta.validation.executable.ExecutableValidator" })
    @EnableConfigurationProperties({ Properties.class })
    @Slf4j
    static class ValidationMessageAutoConfiguration extends I18nValidationBoilerplate implements WebMvcConfigurer {/* @formatter:off */
      protected ValidationMessageAutoConfiguration(MessageSource messageSource, Properties properties) { super(messageSource, properties); }
      /** {@inheritDoc} */ @Override public MessageCodesResolver getMessageCodesResolver() { return properties.i18n.isEnabled() ? messageCodeResolver() : null; }
      /** {@inheritDoc} */ @Override public Validator getValidator() { return properties.i18n.isEnabled() ? validator() : null; }
      /** {@inheritDoc} */ @PostConstruct public void postConstruct() {
        if (properties.i18n.isEnabled()) {
          log.info("ready to I18N support for validation, ( API: \"{}.validation\", prefix: \"{}\" ) .", this instanceof OutdatedValidationMessageAutoConfiguration ? "javax" : "jakarta", properties.i18n.validationMessagePrefix);
        }
      }
    /* @formatter:on */}

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnSingleCandidate(ValidationMessageAutoConfiguration.class)
    @ConditionalOnClass(name = { "javax.validation.executable.ExecutableValidator" })
    @EnableConfigurationProperties({ Properties.class })
    static final class OutdatedValidationMessageAutoConfiguration extends ValidationMessageAutoConfiguration {
      OutdatedValidationMessageAutoConfiguration(MessageSource messageSource, Properties properties) {
        super(messageSource, properties);
      }
    }
    /* @formatter:on */}

  @Configuration(proxyBeanMethods = false)
  @ConditionalOnSingleCandidate(UseragentBoilerplate.class)
  @EnableConfigurationProperties({ Properties.class })
  static final class UseragentAutoConfiguration extends UseragentBoilerplate {
    UseragentAutoConfiguration(Properties properties) {
      super(properties);
    }
  }

  @RequiredArgsConstructor
  @Slf4j
  static abstract class Boilerplate {/* @formatter:off */

    final @Getter(AccessLevel.PROTECTED) Properties properties;
    final @Getter(AccessLevel.PROTECTED) WebProperties webProperties;

    public ErrorViewResolver errorViewResolver(ApplicationContext applicationContext, Resources resources) {
      return new DefaultErrorViewResolver(applicationContext, resources) {
        /** {@inheritDoc} */ @Override public ModelAndView resolveErrorView(HttpServletRequest request, HttpStatus status, Map<String, Object> model) {
          return Trebuchet.Functions.orElse(super.resolveErrorView(request, status, model), (modelAndView) -> {
            Trebuchet.Consumers.orNot(modelAndView, (_modelAndView) -> {
              _modelAndView.getModelMap().addAttribute("traceable", properties.traceableRoles.stream().anyMatch(request::isUserInRole));
              _modelAndView.getModelMap().addAttribute("httpStatus", status);
              Optional.ofNullable(StringUtils.defaultIfBlank(request.getHeader("referer"), null)).ifPresent((referer) -> _modelAndView.getModelMap().addAttribute("previousPage", referer.replaceFirst("https?://[^/]+/", "/")));
              Optional.ofNullable(StringUtils.defaultIfBlank(request.getHeader("referer"), null)).ifPresent((referer) -> _modelAndView.getModelMap().addAttribute("previousPage", referer.replaceFirst("https?://[^/]+/", "/")));
            });

            return modelAndView;
          }, (modelAndView, ex) -> modelAndView);
        }
      };
    }

    /**
     * returns a {@link LocaleChangeInterceptor} .
     *
     * @return {@link LocaleChangeInterceptor}
     */
    protected LocaleChangeInterceptor localeChangeInterceptor() {
      return new LocaleChangeInterceptor() {{
        setIgnoreInvalidLocale(false);
        setParamName(properties.i18n.paramName);
      }};
    }

    /**
     * Overwrite {@link org.springframework.boot.autoconfigure.web.servlet.WebMvcAutoConfiguration.EnableWebMvcConfiguration#localeResolver() EnableWebMvcConfiguration#localeResolver()}
     *
     * @return {@link LocaleResolver}
     */
    protected LocaleResolver localeResolver() {
      return new CookieLocaleResolver(properties.i18n.paramName) {
        {
          sessionLocaleResolver = new SessionLocaleResolver() {{
            setLocaleAttributeName(properties.i18n.paramName);
            setDefaultLocale(properties.i18n.defaultLocale);
            setDefaultTimeZone(properties.i18n.defaultTimeZone);
          }};
          setDefaultLocale(properties.i18n.defaultLocale);
          setDefaultTimeZone(properties.i18n.defaultTimeZone);
          setRejectInvalidCookies(true);

          setCookieDomain(properties.i18n.cookieDomain);
          setCookiePath(StringUtils.defaultIfBlank(properties.i18n.cookiePath, "/"));
          setCookieMaxAge(Duration.ofSeconds(Objects.requireNonNullElse(properties.i18n.cookieMaxAge, -1)));

          setCookieSecure(Objects.requireNonNullElse(properties.i18n.cookieSecure, false));
          setCookieHttpOnly(properties.i18n.cookieHttpOnly);
        }
        final SessionLocaleResolver sessionLocaleResolver;

        /** {@inheritDoc} */ @Override public void setLocale(HttpServletRequest request, HttpServletResponse response, Locale locale) {
          sessionLocaleResolver.setLocale(request, response, locale);
          super.setLocale(request, response, locale);
        }

        /** {@inheritDoc} */ @Override public Locale resolveLocale(HttpServletRequest request) {
          return sessionLocaleResolver.resolveLocale(request);
        }
      };
    }

    /**
     * returns a dialect for thymeleaf template ( s ) .
     *
     * @return {@link LayoutDialect}
     */
    protected LayoutDialect layoutDialect() {
      return new LayoutDialect();
    }

    /**
     * returns web resources that specified in {@link WebProperties} .
     *
     * @return {@link Resources}
     */
    protected Resources resources() {
      return new Resources();
    }

    /** post initialization process . */
    @PostConstruct protected void postConstruct() {
      Optional.ofNullable(webProperties.getLocale()).ifPresent((l) -> SavageReflection.set(properties.i18n, "defaultLocale", l));
      log.info("\n{}\n  i18n      : {}\n  useragent : {}", properties, properties.i18n, properties.useragent);
    }
  /* @formatter:on */}

  @RequiredArgsConstructor
  static abstract class I18nValidationBoilerplate {/* @formatter:off */

    final @Getter(AccessLevel.PROTECTED) MessageSource messageSource;
    final @Getter(AccessLevel.PROTECTED) Properties properties;

    /**
     * returns {@link MessageCodesResolver} that using for validation messages .
     *
     * @return {@link MessageCodesResolver}
     */
    protected MessageCodesResolver messageCodeResolver() {
      return new DefaultMessageCodesResolver() {{ setPrefix(properties.i18n.getValidationMessagePrefix()); }};
    }

    /**
     * returns a {@link Validator} .
     *
     * @return {@link Validator}
     */
    protected Validator validator() {
      return new LocalValidatorFactoryBean() {{
        setValidationMessageSource(messageSource);
        setMessageInterpolator(new LocaleContextMessageInterpolator(new MessageInterpolatorFactory().getObject()));
      }};
    }
  /* @formatter:on */}

  @RequiredArgsConstructor
  @Slf4j
  static abstract class UseragentBoilerplate implements WebMvcConfigurer {/* @formatter:off */

    @Immutable
    @Getter
    @ToString(exclude = { "userAgent" })
    static abstract class UserAgentConscious implements Serializable {

      protected static final String UNKNOWN;
      static { UNKNOWN = StringUtils.defaultIfBlank(CaseFormat.LOWER_UNDERSCORE.to(CaseFormat.LOWER_CAMEL, is.tagomor.woothee.DataSet.VALUE_UNKNOWN), "unknown").toLowerCase(); }

      /** plain text of User-Agent from request . */
      final String userAgent;

      final String category;
      final String name;
      final String os;
      final String osVersion;
      final String vendor;
      final String version;

      UserAgentConscious(String userAgent) {
        final Map<String, String> classified = is.tagomor.woothee.Classifier.parse(userAgent);
        this.userAgent = userAgent;
        category = classified.getOrDefault("category", UNKNOWN);
        name = classified.getOrDefault("name", UNKNOWN);
        os = classified.getOrDefault("os", UNKNOWN);
        osVersion = classified.getOrDefault("os_version", classified.getOrDefault("osVersion", UNKNOWN));
        vendor = classified.getOrDefault("vendor", UNKNOWN);
        version = classified.getOrDefault("version", UNKNOWN);
      }

      public static UserAgentConscious of(final String userAgent) {
        return new UserAgentConscious(userAgent) {};
      }
    }

    final @Getter(AccessLevel.PROTECTED) Properties properties;

    /** {@inheritDoc} */ @Override public void addArgumentResolvers(List<HandlerMethodArgumentResolver> resolvers) {
      if (properties.useragent.isEnabled()) {
        resolvers.add(new HandlerMethodArgumentResolver() {
          /** {@inheritDoc} */ @Override public Object resolveArgument(MethodParameter parameter, ModelAndViewContainer mavContainer, NativeWebRequest webRequest, WebDataBinderFactory binderFactory) throws Exception {
            return UserAgentConscious.of(webRequest.getHeader("User-Agent"));
          }
          /** {@inheritDoc} */ @Override public boolean supportsParameter(MethodParameter parameter) { return UserAgentConscious.class.isAssignableFrom(parameter.getParameterType()); }
        });
      }
    }

    /** {@inheritDoc} */
    @Override
    public void addInterceptors(InterceptorRegistry registry) {
      if (properties.useragent.isEnabled()) {
        registry.addInterceptor(new AsyncHandlerInterceptor() {
          /** {@inheritDoc} */ @Override public void postHandle(HttpServletRequest request, HttpServletResponse response, Object handler, ModelAndView modelAndView) throws Exception {
            if (Trebuchet.Predicates.orNot(handler, (h) -> !((HandlerMethod) h).hasMethodAnnotation(ResponseBody.class))) {
              Optional.ofNullable(modelAndView).ifPresent((mav) -> mav.getModelMap().addAttribute(properties.useragent.attributeName, UserAgentConscious.of(request.getHeader("User-Agent"))));
            }
          }
        });
        registry.addWebRequestInterceptor(new WebRequestInterceptor() {
          /** {@inheritDoc} */ @Override public void afterCompletion(WebRequest request, Exception ex) throws Exception {}
          /** {@inheritDoc} */ @Override public void postHandle(WebRequest request, ModelMap model) throws Exception {
            Optional.ofNullable(model).ifPresent((_model) -> _model.addAttribute(properties.useragent.attributeName, UserAgentConscious.of(request.getHeader("User-Agent"))));
          }
          /** {@inheritDoc} */ @Override public void preHandle(WebRequest request) throws Exception {}
        });
      }
    }

    /** post initialization process . */
    @PostConstruct
    void postConstruct() {
      if (properties.useragent.isEnabled()) {
        log.info("ready to use User-Agent attribute named as \"{}\" .", properties.useragent.attributeName);
      }
    }
  /* @formatter:on */}

  @Immutable
  @ConfigurationProperties(prefix = "project.boilerplate.mvc", ignoreInvalidFields = true, ignoreUnknownFields = true)
  @RequiredArgsConstructor(onConstructor = @__({ @ConstructorBinding }))
  @Value
  static final class Properties {/* @formatter:off */

    @NestedConfigurationProperty
    I18nProperties i18n;

    @NestedConfigurationProperty
    UseragentProperties useragent;

    /** roles who enable to viewing error details in error view ( default: [ 'ROOT', 'ADMIN' ] ) . */ @Getter final List<String> traceableRoles;

    /** post initialization process . */
    @PostConstruct
    protected void postConstruct() {
      Optional.ofNullable(i18n).ifPresentOrElse((x) -> {}, () -> SavageReflection.set(this, "i18n", new I18nProperties(null, null, null, null, null, null, null, null, null, null)));
      Optional.ofNullable(i18n).ifPresent(I18nProperties::defaults);
      Optional.ofNullable(useragent).ifPresentOrElse((x) -> {}, () -> SavageReflection.set(this, "useragent", new UseragentProperties(null, null)));
      Optional.ofNullable(useragent).ifPresent(UseragentProperties::defaults);
      SavageReflection.set(this, "traceableRoles", Stream.of(
          Stream.of("root", "admin")
        , Optional.ofNullable(traceableRoles).orElseGet(ArrayList::new).stream()
        ).flatMap((x) -> x)
        .map(Objects::toString).map((role) -> CaseFormat.LOWER_CAMEL.to(CaseFormat.UPPER_UNDERSCORE, Arrays.stream(role.split("[\\s　]+")).map(StringUtils::capitalize).filter(StringUtils::isNotBlank).collect(Collectors.joining())))
        .filter(StringUtils::isNotBlank).distinct().collect(Collectors.toUnmodifiableList()));
    }
  /* @formatter:on */}

  @Immutable
  @ConfigurationProperties(prefix = "project.boilerplate.mvc.i18n", ignoreInvalidFields = true, ignoreUnknownFields = true)
  @RequiredArgsConstructor(onConstructor = @__({ @ConstructorBinding }))
  @Value
  static class I18nProperties {/* @formatter:off */

    /** if true, enable to I18N support ( default: {@code true} ) . */ @Getter final Boolean enabled;

    /** default locale ( default: {@link Locale#getDefault()} ) . */ @Getter final Locale defaultLocale = Locale.getDefault();

    /** default time-zone ( default: {@link TimeZone#getDefault()} ) . */ @Getter final TimeZone defaultTimeZone = TimeZone.getDefault();

    /** parameter name to change locale ( default: {@code "locale"} ) . */ @Getter final String paramName;

    /** default locale ( default: {@link MvcBoilerplate.I18nProperties#defaultLocale defaultLocale.toString()} ) . */ @Getter final String locale;

    /** default time-zone ( {@link MvcBoilerplate.I18nProperties#defaultTimeZone defaultTimeZone.toString()} ) . */ @Getter final String timeZone;

    /** prefix of resource message bundle(s) for validation ( default: {@code ""} ) . */ @Getter final String validationMessagePrefix;

    /** the domain of the cookie that the expected CSRF token is saved to and read from (default: {@code null} ) . */ @Getter() final String cookieDomain;

    /** the path that the Cookie will be created with (default: {@code null} ) . */ @Getter() final String cookiePath;

    /** maximum age in seconds for the cookie that the expected CSRF token is saved to and read from (default: {@code -1} ) . */ @Getter() final Integer cookieMaxAge;

    /** secure flag of the cookie that the expected CSRF token is saved to and read from (default: {@code null} ) . */ @Getter() final Boolean cookieSecure;

    /** if true, to mark the cookie as HTTP only ( default: {@code true} ) . */ @Getter() final Boolean cookieHttpOnly;

    /**
     * alias of {@link #getEnabled()} .
     *
     * @return {@link #enabled}
     */
    public boolean isEnabled() { return enabled; }

    /** post initialization process . */
    @PostConstruct
    protected void postConstruct() { defaults(); }

    private final void defaults() {
      Optional.ofNullable(enabled).ifPresentOrElse((x) -> {}, () -> SavageReflection.set(this, "enabled", true));
      Optional.ofNullable(Trebuchet.Functions.orNot(locale, Localizr::getLocale)).ifPresent((l) -> SavageReflection.set(this, "defaultLocale", l));
      SavageReflection.set(this, "locale", defaultLocale.toString());
      Optional.ofNullable(Trebuchet.Functions.orNot(timeZone, Localizr::getTimeZone)).ifPresent((tz) -> SavageReflection.set(this, "defaultTimeZone", tz));
      SavageReflection.set(this, "timeZone", defaultTimeZone.toString());
      SavageReflection.set(this, "paramName", CaseFormat.LOWER_UNDERSCORE.to(CaseFormat.LOWER_CAMEL, Objects.requireNonNullElse(StringUtils.defaultIfBlank(paramName, null), LocaleChangeInterceptor.DEFAULT_PARAM_NAME).replaceAll("[\\p{javaWhitespace}\\n_]+", "_")));
      Optional.ofNullable(validationMessagePrefix).ifPresentOrElse((p) -> {}, () -> SavageReflection.set(this, "validationMessagePrefix", ""));
      SavageReflection.set(this, "cookieDomain", Objects.toString(cookieDomain, ""));
      SavageReflection.set(this, "cookiePath", Objects.toString(cookiePath, ""));
      Optional.ofNullable(cookieMaxAge).ifPresentOrElse((x) -> {}, () -> SavageReflection.set(this, "cookieMaxAge", -1));
      Optional.ofNullable(cookieHttpOnly).ifPresentOrElse((x) -> {}, () -> SavageReflection.set(this, "cookieHttpOnly", true));
    }
  /* @formatter:on */}

  @Immutable
  @ConfigurationProperties(prefix = "project.boilerplate.mvc.useragent", ignoreInvalidFields = true, ignoreUnknownFields = true)
  @RequiredArgsConstructor(onConstructor = @__({ @ConstructorBinding }))
  @Value
  static class UseragentProperties {/* @formatter:off */

    /** if true, adds user-agent support ( default: {@code true} ) . */ @Getter() final Boolean enabled;

    /** attribute name of user-agent attribute ( default: {@code "userAgent"} ) . */ @Getter final String attributeName;

    /**
     * alias of {@link #getEnabled()} .
     *
     * @return {@link #enabled}
     */
    public boolean isEnabled() { return enabled; }

    /** post initialization process . */
    @PostConstruct
    protected void postConstruct() { defaults(); }

    private final void defaults() {
      Optional.ofNullable(enabled).ifPresentOrElse((x) -> {}, () -> SavageReflection.set(this, "enabled", true));
      SavageReflection.set(this, "attributeName", CaseFormat.LOWER_UNDERSCORE.to(CaseFormat.LOWER_CAMEL, Objects.requireNonNullElse(StringUtils.defaultIfBlank(attributeName, null), "user_agent").replaceAll("[\\p{javaWhitespace}\\n_]+", "_")));
    }
  /* @formatter:on */}
}
