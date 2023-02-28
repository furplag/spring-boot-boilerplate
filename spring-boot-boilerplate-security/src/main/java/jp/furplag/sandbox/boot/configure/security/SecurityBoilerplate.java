package jp.furplag.sandbox.boot.configure.security;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.annotation.PostConstruct;
import javax.annotation.concurrent.Immutable;
import javax.security.auth.login.AccountExpiredException;
import javax.security.auth.login.CredentialExpiredException;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnSingleCandidate;
import org.springframework.boot.autoconfigure.security.oauth2.client.ClientsConfiguredCondition;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientPropertiesRegistrationAdapter;
import org.springframework.boot.autoconfigure.web.servlet.WebMvcAutoConfiguration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.ConstructorBinding;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.AnonymousConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.security.web.csrf.LazyCsrfTokenRepository;
import org.springframework.security.web.csrf.MissingCsrfTokenException;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.multipart.support.MultipartFilter;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import jp.furplag.sandbox.reflect.SavageReflection;
import jp.furplag.sandbox.text.Commonizr;
import jp.furplag.sandbox.trebuchet.Trebuchet;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

public interface SecurityBoilerplate {

  @RequiredArgsConstructor
  @Slf4j
  static abstract class Boilerplate extends WebSecurityConfigurerAdapter {/* @formatter:off */

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnSingleCandidate(Boilerplate.class)
    @EnableConfigurationProperties({ Properties.class, OAuth2ClientProperties.class })
    static final class AutoConfiguration extends Boilerplate implements Ordered {
      AutoConfiguration(Properties properties, OAuth2ClientProperties oAuth2ClientProperties, ServletContext servletContext) { super(properties, oAuth2ClientProperties, servletContext); }
      /** {@inheritDoc} */ @Bean @Override public AccessDeniedHandler accessDeniedHandler() { return super.accessDeniedHandler(); }
      /** {@inheritDoc} */ @Bean @Override public AuthenticationEntryPoint authenticationEntryPoint() { return super.authenticationEntryPoint(); }
      /** {@inheritDoc} */ @Bean @Override public AuthenticationManager authenticationManager() throws Exception { return super.authenticationManager(); }
      /** {@inheritDoc} */ @Bean @Override public PasswordEncoder passwordEncoder() { return super.passwordEncoder(); }
      /** {@inheritDoc} */ @Bean @Override public UserDetailsService userDetailsService() { return super.userDetailsService(); }
      /** {@inheritDoc} */ @Bean @Conditional(ClientsConfiguredCondition.class) @Override public ClientRegistrationRepository clientRegistrationRepository() { return super.clientRegistrationRepository(); }
      /** {@inheritDoc} */ @Override public int getOrder() { return super.getOrder(); }
      /** {@inheritDoc} */ @PostConstruct @Override public void postConstruct() {
        super.postConstruct();
        log.warn("security alert: should not use default \"jp.furplag.sandbox.boot.security.LoginFlowConfigurer#userDetailsService()\" in production .");
      }
    }

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnProperty(prefix = "project.boilerplate.security.form-login", name = "enabled", matchIfMissing = true)
    @ConditionalOnBean(Boilerplate.AutoConfiguration.class)
    @ConditionalOnSingleCandidate(FormLogin.class)
    @AutoConfigureAfter({ Boilerplate.AutoConfiguration.class, WebMvcAutoConfiguration.class })
    @EnableConfigurationProperties({ Properties.class })
    @Controller
    static final class FormLoginViews extends FormLogin {}

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnProperty(prefix = "project.boilerplate.security.form-login", name = "enabled", matchIfMissing = true)
    @ConditionalOnBean(Boilerplate.AutoConfiguration.class)
    @ConditionalOnSingleCandidate(FormLoginFailure.class)
    @AutoConfigureAfter({ Boilerplate.AutoConfiguration.class, WebMvcAutoConfiguration.class })
    @EnableConfigurationProperties({ Properties.class })
    @Controller
    static final class FormLoginFailureViews extends FormLoginFailure {}

    final @Getter(AccessLevel.PROTECTED) Properties properties;

    final @Getter(AccessLevel.PROTECTED) OAuth2ClientProperties oAuth2ClientProperties;

    final @Getter(AccessLevel.PROTECTED) ServletContext servletContext;

    /** {@inheritDoc} */ @Override protected void configure(AuthenticationManagerBuilder auth) throws Exception {
      auth.eraseCredentials(true).userDetailsService(userDetailsService()).passwordEncoder(passwordEncoder());
    }

    /** {@inheritDoc} */ @Override protected void configure(HttpSecurity http) throws Exception {
      Trebuchet.Functions.orElse(http, (h) -> {
        configureCsrf(h);
        configureFormLogin(h);
        configureBasicAuth(h);

        return h;
      }, (h, ex) -> { log.error("{}", ex.getLocalizedMessage()); return h; })
      .anonymous()
      .and().headers()
        .frameOptions().disable()
      .and().sessionManagement()
        .maximumSessions(-1)
      .and().sessionFixation()
        .migrateSession();
    }

    /** {@inheritDoc} */ @Override public void configure(WebSecurity web) throws Exception {
      Trebuchet.Consumers.orNot(web.debug(properties.isDebug()), properties.ignores.isEmpty() ? null : properties.ignores, (_web, ignores) -> _web.ignoring().antMatchers(ignores.toArray(String[]::new)));
    }

    /**
     * configure HTTP Basic authentication .
     *
     * @param http the {@link HttpSecurity} to modify
     * @throws Exception
     */
    protected void configureBasicAuth(HttpSecurity http) throws Exception {
      http.httpBasic((t) -> { if (!properties.basic.enabled) { t.disable(); } });
    }

    /**
     * CSRF configuration .
     *
     * @param http the {@link HttpSecurity} to modify
     * @throws Exception
     */
    protected void configureCsrf(HttpSecurity http) throws Exception {
      if (!properties.csrf.enabled) { http.csrf().disable(); return; }
      http.csrf((t) -> t
        .csrfTokenRepository(csrfTokenRepository())
        .ignoringAntMatchers(properties.csrf.ignores.toArray(String[]::new)))
      .addFilterBefore(new MultipartFilter() {{ setServletContext(servletContext); }}, CsrfFilter.class);
    }

    /**
     * configure form based authentication .
     *
     * @param http the {@link HttpSecurity} to modify
     * @throws Exception
     */
    protected void configureFormLogin(HttpSecurity http) throws Exception {
      if (!properties.formLogin.enabled) {
        http.authorizeRequests((t) -> t
          .mvcMatchers((properties.basic.enabled ? properties.formLogin.anonymouslyAccessibles : List.of("/**")).stream().distinct().toArray(String[]::new)).permitAll()
          .mvcMatchers("/actuator/**" /* ignore any roles if no login flows . */).hasAnyRole("ACTUATOR", "ROOT")
          .anyRequest().authenticated())
        .formLogin().disable()
        .anonymous((t) -> Optional.ofNullable(properties.basic.enabled || properties.formLogin.enabled ? null : t).ifPresent(AnonymousConfigurer::disable));

        return;
      }
      http.authorizeRequests((t) -> t
        .mvcMatchers(properties.formLogin.anonymouslyAccessibles.stream().distinct().toArray(String[]::new)).permitAll()
        .mvcMatchers("/actuator/**").hasAnyRole("ACTUATOR", "ROOT")
        .anyRequest().authenticated())
      .formLogin((t) -> t
        .loginPage(properties.formLogin.loginUrl)
        .loginProcessingUrl(properties.formLogin.loginProcessingUrl)
        .failureHandler(authenticationFailureHandler())
        .successHandler(authenticationSuccessHandler())
        .usernameParameter(properties.formLogin.usernameParameter)
        .passwordParameter(properties.formLogin.passwordParameter))
      .logout((t) ->
        Trebuchet.Functions.orElse(t, properties.formLogin.logoutUrl, properties.formLogin.logoutConfirmRequired ? (_t, u) -> _t.logoutUrl(u) : (_t, u) -> _t.logoutRequestMatcher(new AntPathRequestMatcher(u, null, false)), (_t, u, ex) -> _t)
        .logoutSuccessUrl(properties.formLogin.logoutSuccessUrl)
        .clearAuthentication(true)
        .deleteCookies("JSESSIONID", "jsessionid")
        .invalidateHttpSession(true))
      .exceptionHandling((t) -> t
        .authenticationEntryPoint(authenticationEntryPoint())
        .accessDeniedHandler(accessDeniedHandler()))
      .anonymous().disable()
      ;
    }

    /**
     * configure OAuth authentication .
     *
     * @param http the {@link HttpSecurity} to modify
     * @throws Exception
     */
    protected void configureOAuth2Login(HttpSecurity http) throws Exception {
      if (!properties.oAuth2Login.enabled) { http.csrf().disable(); return; }
      http.oauth2Client((t) -> t
        .clientRegistrationRepository(clientRegistrationRepository())
      );
    }

    /**
     * Used by ExceptionTranslationFilter to handle an AccessDeniedException .
     *
     * @return {@link AccessDeniedHandler}
     */
    protected AccessDeniedHandler accessDeniedHandler() {
      return new AccessDeniedHandler() {
        /** {@inheritDoc} */ @Override public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
          if (accessDeniedException instanceof MissingCsrfTokenException) {
            authenticationEntryPoint().commence(request, response, new AuthenticationCredentialsNotFoundException("Session expired", accessDeniedException));
          } else {
            new AccessDeniedHandlerImpl().handle(request, response, accessDeniedException);
          }
        }
      };
    }

    /**
     * Used by ExceptionTranslationFilter to commence an authentication scheme .
     *
     * @return {@link AuthenticationEntryPoint}
     */
    protected AuthenticationEntryPoint authenticationEntryPoint() {
      return new LoginUrlAuthenticationEntryPoint(properties.formLogin.loginUrl) {
        /** {@inheritDoc} */ @Override public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
          response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
          if (!"XMLHttpRequest".equals(request.getHeader("X-Requested-With"))) {
            super.commence(request, response, authException);
          }
        }

        /** {@inheritDoc} */ @Override public String buildRedirectUrlToLoginPage(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) {
          final boolean sessionExpired = StringUtils.isNotBlank(request.getRequestedSessionId()) && !request.isRequestedSessionIdValid();
          if (sessionExpired) {
            Optional.ofNullable(request.getSession().getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION)).ifPresentOrElse((ex) -> {}, () -> {
              request.getSession().setAttribute(WebAttributes.AUTHENTICATION_EXCEPTION, new AuthenticationCredentialsNotFoundException("Session expired"));
            });
          }
          return super.buildRedirectUrlToLoginPage(request, response, authException);
        }
      };
    }

    /**
     * specifies the {@link AuthenticationFailureHandler} to use when authentication fails .
     *
     * @return {@link AuthenticationFailureHandler}
     */
    protected AuthenticationFailureHandler authenticationFailureHandler() {
      return new SimpleUrlAuthenticationFailureHandler(properties.formLogin.loginFailureUrl) {
        /** {@inheritDoc} */ @Override public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
          saveException(request, exception);
          ((RedirectStrategy) Trebuchet.Functions.orElse(this, "redirectStrategy", SavageReflection::get, DefaultRedirectStrategy::new)).sendRedirect(request, response, Stream.of(
              Map.entry(DisabledException.class, "/error/disabled")
            , Map.entry(LockedException.class, "/error/locked")
            , Map.entry(AccountExpiredException.class, "/error/expired/account")
            , Map.entry(CredentialExpiredException.class, "/error/expired/credential")
          ).filter((e) -> e.getKey().isInstance(exception)).map(Map.Entry::getValue).findFirst().orElse(properties.formLogin.loginFailureUrl));
        }
      };
    }

    /**
     * specifies the {@link AuthenticationSuccessHandler} to be used .
     *
     * @return {@link AuthenticationSuccessHandler}
     */
    protected AuthenticationSuccessHandler authenticationSuccessHandler() {
      return new SavedRequestAwareAuthenticationSuccessHandler() {{
        setDefaultTargetUrl(properties.formLogin.loginSuccessUrl);
        setAlwaysUseDefaultTargetUrl(false);
        setUseReferer(true);
      }};
    }

    /**
     * {@link Configuration @Configuration} used to map {@link OAuth2ClientProperties} to client registrations .
     *
     * @return {@link InMemoryClientRegistrationRepository}
     */
    protected ClientRegistrationRepository clientRegistrationRepository() {
      return new InMemoryClientRegistrationRepository(
        Optional.ofNullable(Trebuchet.Functions.orNot(oAuth2ClientProperties, OAuth2ClientPropertiesRegistrationAdapter::getClientRegistrations))
        .orElseGet(Collections::emptyMap).entrySet().stream().toArray(ClientRegistration[]::new));
    }

    /**
     * specifies the {@link CsrfTokenRepository} to be used .
     *
     * @return {@link CsrfTokenRepository}
     */
    protected CsrfTokenRepository csrfTokenRepository() {
      return new LazyCsrfTokenRepository(new CsrfTokenRepository() {
        private final HttpSessionCsrfTokenRepository httpSessionCsrfTokenRepository = new HttpSessionCsrfTokenRepository();
        {
          httpSessionCsrfTokenRepository.setHeaderName(properties.csrf.headerName);
          httpSessionCsrfTokenRepository.setParameterName(properties.csrf.parameterName);
          httpSessionCsrfTokenRepository.setSessionAttributeName(properties.csrf.sessionAttributeName);
        }

        /** {@inheritDoc} */
        @Override
        public void saveToken(CsrfToken token, HttpServletRequest request, HttpServletResponse response) {
          httpSessionCsrfTokenRepository.saveToken(token, request, response);
          response.addCookie(new Cookie(properties.csrf.cookieName, StringUtils.defaultIfBlank(Trebuchet.Functions.orNot(token, CsrfToken::getToken), "")) {{
            setSecure(Objects.requireNonNullElse(properties.csrf.cookieSecure, request.isSecure()));
            setPath(StringUtils.defaultIfBlank(properties.csrf.cookiePath, StringUtils.defaultIfBlank(request.getContextPath(), "/")));
            setMaxAge(token == null ? 0 : properties.csrf.cookieMaxAge);
            setHttpOnly(properties.csrf.cookieHttpOnly);
            setDomain(properties.csrf.cookieDomain);
          }});
        }

        /** {@inheritDoc} */ @Override public CsrfToken loadToken(HttpServletRequest request) { return httpSessionCsrfTokenRepository.loadToken(request); }

        /** {@inheritDoc} */ @Override public CsrfToken generateToken(HttpServletRequest request) { return httpSessionCsrfTokenRepository.generateToken(request); }
      });
    }

    /**
     * get the order value of this object .
     *
     * @return lower than {@link WebSecurityConfigurerAdapter}'s order .
     */
    public int getOrder() { return Trebuchet.Functions.orElse(WebSecurityConfigurerAdapter.class.getAnnotation(Order.class), Order::value, () -> 100) - 1; }

    /**
     * register Bean any of {@link PasswordEncoder} .
     *
     * @return {@link PasswordEncoder}
     */
    protected PasswordEncoder passwordEncoder() {
      return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    /** {@inheritDoc} */ @Override public UserDetailsService userDetailsService() {
      return new UserDetailsService() {
        /** {@inheritDoc} */
        @Override
        public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
          final String _username = StringUtils.defaultIfBlank(Commonizr.trim(username), "").toLowerCase();
          return Optional.ofNullable(Set.of("", "notexists", "anonymous").contains(_username) ? null : new UserDetails() {
            /** {@inheritDoc} */ @Override public Collection<? extends GrantedAuthority> getAuthorities() {
              return AuthorityUtils.commaSeparatedStringToAuthorityList(Stream.of(_username.toUpperCase(), "USER").filter(StringUtils::isNotBlank).distinct().collect(Collectors.joining(",ROLE_", "ROLE_", "")));
            }
            /** {@inheritDoc} */ @Override public String getPassword() { return passwordEncoder().encode(getUsername()); }
            /** {@inheritDoc} */ @Override public String getUsername() { return _username; }
            /** {@inheritDoc} */ @Override public boolean isAccountNonExpired() { return !"accountExpired".equalsIgnoreCase(getUsername()); }
            /** {@inheritDoc} */ @Override public boolean isAccountNonLocked() { return !"accountLocked".equalsIgnoreCase(getUsername()); }
            /** {@inheritDoc} */ @Override public boolean isCredentialsNonExpired() { return !"credentialExpired".equalsIgnoreCase(getUsername()); }
            /** {@inheritDoc} */ @Override public boolean isEnabled() { return !"disabled".equals(getUsername()); }
            /** {@inheritDoc} */ @Override public String toString() {
              return Map.ofEntries(
                Map.entry("username", getUsername())
              , Map.entry("password", "[INSECURED]")
              , Map.entry("authorities", getAuthorities().toString())
              ).toString();
            }
          }).orElseThrow(() -> new UsernameNotFoundException(String.format("\"%s\" not exists .", Objects.toString(username, "[empty]"))));
        }
      };
    }

    @PostConstruct protected void postConstruct() {
      log.info("\n{}\n  basic    : {}\n  csrf     : {}\n  formLogin: {}\n  oAuth2Login: {}", properties, properties.basic, properties.csrf, properties.formLogin, properties.oAuth2Login);
    }
  /* @formatter:on */}

  @RequiredArgsConstructor
  static abstract class FormLogin {/* @formatter:off */

    @Autowired
    @Getter(AccessLevel.PROTECTED)
    Properties properties;

    @RequestMapping({ "/" })
    public String index(HttpServletRequest request, HttpServletResponse response, Authentication authentication, Model model, RedirectAttributes attributes) {
      return "index";
    }

    @GetMapping({ "#{T(org.apache.commons.lang3.StringUtils).defaultIfBlank('${project.boilerplate.security.form-login.login-url:}', '/login')}" })
    public String login(HttpServletRequest request, HttpServletResponse response, Authentication authentication, Model model, RedirectAttributes attributes) {
      if (Trebuchet.Predicates.orNot(authentication, Authentication::isAuthenticated)) {
        return "redirect:/";
      }
      List.of(WebAttributes.AUTHENTICATION_EXCEPTION, WebAttributes.ACCESS_DENIED_403).forEach((attributeName) ->
        Optional.ofNullable(request.getSession().getAttribute(attributeName)).ifPresent((exception) -> {
          model.addAttribute(attributeName, exception);
          request.getSession().removeAttribute(attributeName);
        }));
      Stream.of(WebAttributes.ACCESS_DENIED_403, WebAttributes.AUTHENTICATION_EXCEPTION).filter(model::containsAttribute).findFirst().ifPresent((attributeName) -> {
        response.setStatus(WebAttributes.ACCESS_DENIED_403.equals(attributeName) ? HttpServletResponse.SC_FORBIDDEN : HttpServletResponse.SC_UNAUTHORIZED);
      });

      return "login/index";
    }

    @RequestMapping({ "#{T(org.apache.commons.lang3.StringUtils).defaultIfBlank('${project.boilerplate.security.form-login.login-success-url:}', '/home')}" })
    public String home(HttpServletRequest request, HttpServletResponse response, Authentication authentication, Model model, RedirectAttributes attributes) {
      return (properties.formLogin.gatewayEnabled || (authentication.getPrincipal() != null && !request.isUserInRole("ROLE_ANONYMOUS")))
        ? index(request, response, authentication, model, attributes)
        : login(request, response, authentication, model, attributes);
    }
  /* @formatter:on */}

  @RequiredArgsConstructor
  static abstract class FormLoginFailure {/* @formatter:off */

    @Autowired
    @Getter(AccessLevel.PROTECTED)
    Properties properties;

    @RequestMapping({ "/error/disabled" })
    public String disabled(HttpServletRequest request, HttpServletResponse response, Authentication authentication, Model model, RedirectAttributes attributes) {
      return unauthorized(request, response, authentication, model, attributes);
    }

    @RequestMapping({ "/error/expired/account", "/error/expired/credencial" })
    public String expired(HttpServletRequest request, HttpServletResponse response, Authentication authentication, Model model, RedirectAttributes attributes) {
      return unauthorized(request, response, authentication, model, attributes);
    }

    @RequestMapping({ "/error/locked" })
    public String locked(HttpServletRequest request, HttpServletResponse response, Authentication authentication, Model model, RedirectAttributes attributes) {
      return unauthorized(request, response, authentication, model, attributes);
    }

    @RequestMapping({ "/error#{T(org.apache.commons.lang3.StringUtils).defaultIfBlank('${project.boilerplate.security.form-login.login-failure-url:}', '/unauthorized')}", "#{T(org.apache.commons.lang3.StringUtils).defaultIfBlank('${project.boilerplate.security.form-login.login-failure-url:}', '/unauthorized')}" })
    public String unauthorized(HttpServletRequest request, HttpServletResponse response, Authentication authentication, Model model, RedirectAttributes attributes) {
      if (Trebuchet.Predicates.orNot(authentication, Authentication::isAuthenticated)) {
        return String.format("redirect:%s", properties.formLogin.loginSuccessUrl);
      }
      List.of(WebAttributes.AUTHENTICATION_EXCEPTION, WebAttributes.ACCESS_DENIED_403).forEach((attributeName) ->
      Optional.ofNullable(request.getSession().getAttribute(attributeName)).ifPresent((exception) -> {
        attributes.addFlashAttribute(attributeName, exception);
        request.getSession().removeAttribute(attributeName);
      }));

      return String.format("redirect:%s", properties.formLogin.loginUrl);
    }
  /* @formatter:on */}

  @Immutable
  @ConstructorBinding
  @ConfigurationProperties(prefix = "project.boilerplate.security", ignoreInvalidFields = true, ignoreUnknownFields = true)
  @lombok.Value
  static final class Properties {/* @formatter:off */

    @NestedConfigurationProperty BasicAuthProperties basic;

    @NestedConfigurationProperty CsrfProperties csrf;

    /** enable to debugging {@link org.springframework.security.config.annotation.web.builders.WebSecurity#debug(boolean) WebSecurity#debug(boolean)}, if true ( default: {@code false} ) . */ @Getter final Boolean debug;

    @NestedConfigurationProperty FormloginProperties formLogin;

    @NestedConfigurationProperty OAuth2LoginProperties oAuth2Login;

    /** path patterns which ignores any security protection ( default: empty ) . */ @Getter final List<String> ignores;

    /**
     * alias of {@link #getDebug()} .
     *
     * @return {@link #debug}
     */
    public boolean isDebug() { return getDebug(); }

    @PostConstruct
    protected void postConstruct() {
      Optional.ofNullable(basic).ifPresentOrElse((x) -> {}, () -> SavageReflection.set(this, "basic", new BasicAuthProperties(false)));
      Optional.ofNullable(basic).ifPresent(BasicAuthProperties::defaults);
      Optional.ofNullable(csrf).ifPresentOrElse((x) -> {}, () -> SavageReflection.set(this, "csrf", new CsrfProperties(true, null, null, null, null, null, null, null, null, null, true)));
      Optional.ofNullable(csrf).ifPresent(CsrfProperties::defaults);
      Optional.ofNullable(debug).ifPresentOrElse((x) -> {}, () -> SavageReflection.set(this, "debug", false));
      Optional.ofNullable(formLogin).ifPresentOrElse((x) -> {}, () -> SavageReflection.set(this, "formLogin", new FormloginProperties(null, true, false, null, null, null, null, false, null, null, null, null, null, null)));
      Optional.ofNullable(formLogin).ifPresent(FormloginProperties::defaults);
      Optional.ofNullable(oAuth2Login).ifPresentOrElse((x) -> {}, () -> SavageReflection.set(this, "oAuth2Login", new OAuth2LoginProperties(false)));
      Optional.ofNullable(oAuth2Login).ifPresent(OAuth2LoginProperties::defaults);
      SavageReflection.set(this, "ignores", Optional.ofNullable(ignores).orElseGet(ArrayList::new).stream().filter(StringUtils::isNotBlank).distinct().collect(Collectors.toUnmodifiableList()));
    }
  /* @formatter:on */}

  /**
   * HTTP Basic authentication .
   *
   * @author furplag
   *
   */
  @Immutable
  @ConstructorBinding
  @ConfigurationProperties(prefix = "project.boilerplate.security.basic", ignoreInvalidFields = true, ignoreUnknownFields = true)
  @lombok.Value
  static class BasicAuthProperties {/* @formatter:off */

    /** if true, enable to HTTP Basic authentication ( default: {@code false} ) . */ @Getter final Boolean enabled;

    /**
     * alias of {@link #getEnabled()} .
     *
     * @return {@link #enabled}
     */
    public boolean isEnabled() { return enabled; }

    @PostConstruct
    protected void postConstruct() {
      defaults();
    }

    private final void defaults() {
      Optional.ofNullable(enabled).ifPresentOrElse((x) -> {}, () -> SavageReflection.set(this, "enabled", false));
    }
  /* @formatter:on */}

  /**
   * CSRF protection .
   *
   * @author furplag
   *
   */
  @Immutable
  @ConstructorBinding
  @ConfigurationProperties(prefix = "project.boilerplate.security.csrf", ignoreInvalidFields = true, ignoreUnknownFields = true)
  @lombok.Value
  static class CsrfProperties {/* @formatter:off */

    /** if true, adds CSRF support ( default: {@code true} ) . */ @Getter() final Boolean enabled;

    /** path patterns which ignores CSRF protection ( default: [ "/api/public/**" ] ) . */ @Getter final List<String> ignores;

    /** parameter name of CSRF Token in requests ( default: "_csrf" ) . */ @Getter final String parameterName;

    /** attribute name of header that should be used to provide the token ( default: "XSRF-TOKEN" ) . */ @Getter final String cookieName;

    /** the header name of CSRF Token via response ( default: "X-XSRF-TOKEN" ) . */ @Getter final String headerName;

    /** attribute name of CSRF Token which HTTP session stores in ( default: "CSRF_TOKEN" ) . */ @Getter final String sessionAttributeName;

    /** the domain of the cookie that the expected CSRF token is saved to and read from (default: {@code null} ) . */ @Getter() final String cookieDomain;

    /** the path that the Cookie will be created with (default: {@code null} ) . */ @Getter() final String cookiePath;

    /** maximum age in seconds for the cookie that the expected CSRF token is saved to and read from (default: {@code -1} ) . */ @Getter() final Integer cookieMaxAge;

    /** secure flag of the cookie that the expected CSRF token is saved to and read from (default: {@code null} ) . */ @Getter() final Boolean cookieSecure;

    /** if true, to mark the cookie as HTTP only ( default: {@code true} ) . */ @Getter() final Boolean cookieHttpOnly;

    /**
     * alias of {@link #getCookieHttpOnly()} .
     *
     * @return {@link #cookieHttpOnly}
     */
    public boolean iscookieHttpOnly() { return cookieHttpOnly; }

    /**
     * alias of {@link #getEnabled()} .
     *
     * @return {@link #enabled}
     */
    public boolean isEnabled() { return enabled; }

    @PostConstruct
    protected void postConstruct() {
      defaults();
    }

    private final void defaults() {
      Optional.ofNullable(enabled).ifPresentOrElse((x) -> {}, () -> SavageReflection.set(this, "enabled", true));
      Optional.ofNullable(StringUtils.defaultIfBlank(parameterName, null)).ifPresentOrElse((x) -> {}, () -> SavageReflection.set(this, "parameterName", Objects.toString(SavageReflection.get(org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository.class, "DEFAULT_CSRF_PARAMETER_NAME"), "_csrf")));
      Optional.ofNullable(StringUtils.defaultIfBlank(cookieName, null)).ifPresentOrElse((x) -> {}, () -> SavageReflection.set(this, "cookieName", Objects.toString(SavageReflection.get(org.springframework.security.web.csrf.CookieCsrfTokenRepository.class, "DEFAULT_CSRF_COOKIE_NAME"), "XSRF-TOKEN")));
      Optional.ofNullable(StringUtils.defaultIfBlank(headerName, null)).ifPresentOrElse((x) -> {}, () -> SavageReflection.set(this, "headerName", Objects.toString(SavageReflection.get(org.springframework.security.web.csrf.CookieCsrfTokenRepository.class, "DEFAULT_CSRF_HEADER_NAME"), "X-XSRF-TOKEN")));
      Optional.ofNullable(StringUtils.defaultIfBlank(sessionAttributeName, null)).ifPresentOrElse((x) -> {}, () -> SavageReflection.set(this, "sessionAttributeName", "CSRF_TOKEN"));
      SavageReflection.set(this, "cookieDomain", Objects.toString(cookieDomain, ""));
      SavageReflection.set(this, "cookiePath", Objects.toString(cookiePath, ""));
      Optional.ofNullable(cookieMaxAge).ifPresentOrElse((x) -> {}, () -> SavageReflection.set(this, "cookieMaxAge", -1));
      Optional.ofNullable(cookieHttpOnly).ifPresentOrElse((x) -> {}, () -> SavageReflection.set(this, "cookieHttpOnly", true));

      SavageReflection.set(this, "ignores", Stream.of(
          Optional.ofNullable(ignores).orElseGet(ArrayList::new).stream()
        , List.of(Optional.ofNullable(ignores).orElseGet(ArrayList::new).isEmpty() ? "/api/public/**" : "").stream()
      ).flatMap((x) -> x).filter(StringUtils::isNotBlank).distinct().collect(Collectors.toUnmodifiableList()));
    }
  /* @formatter:on */}

  /**
   * form based authentication .
   *
   * @author furplag
   *
   */
  @Immutable
  @ConstructorBinding
  @ConfigurationProperties(prefix = "project.boilerplate.security.form-login", ignoreInvalidFields = true, ignoreUnknownFields = true)
  @lombok.Value
  static class FormloginProperties {/* @formatter:off */

    /** path patterns of accessible anonymously ( default: static resources, "/error" "/webjars" and few paths which necesaly to access before authentication ) . */ @Getter final List<String> anonymouslyAccessibles;

    /** if true, enable to Form login ( default: {@code true} ) . */ @Getter final Boolean enabled;

    /** enable to access index page ( "/", "/index*" ) anonymously, if true ( default: {@code true} ) . */ @Getter final Boolean gatewayEnabled;

    /** login URL ( default: "/login" ) . */ @Getter final String loginUrl;

    /** login URL ( default: {@link #loginUrl} ) . */ @Getter final String loginProcessingUrl;

    /** a redirect URL for 401 ( default: "/unauthorized" ) . */ @Getter final String loginFailureUrl;

    /** a redirect URL for users ( default: "/home" ) . */ @Getter final String loginSuccessUrl;

    /** confirming before logged out, if true ( default: {@code false} ) . */ @Getter final Boolean logoutConfirmRequired;

    /** logout URL ( default: "/logout" ) . */ @Getter final String logoutUrl;

    /** logout URL ( default: {@link #logoutUrl} ) . */ @Getter final String logoutProcessingUrl;

    /** a redirect URL for logged out ( default: "/" ) . */ @Getter final String logoutSuccessUrl;

    /** a redirect URL if session expired ( default: "/expired" ) . */ @Getter final String sessionExpiredUrl;

    /** the HTTP parameter to look for the password when performing authentication ( default: "username" ) . */ @Getter final String usernameParameter;

    /** the HTTP parameter to look for the password when performing authentication ( default: "password" ) . */ @Getter final String passwordParameter;

    /**
     * alias of {@link #getEnabled()} .
     *
     * @return {@link #enabled}
     */
    public boolean isEnabled() { return enabled; }

    /**
     * alias of {@link #getGatewayEnabled()} .
     *
     * @return {@link #gatewayEnabled}
     */
    public boolean isGatewayEnabled() { return getGatewayEnabled(); }

    /**
     * alias of {@link #getLogoutConfirmRequired()} .
     *
     * @return {@link #logoutConfirmRequired}
     */
    public boolean isLogoutConfirmRequired() { return getLogoutConfirmRequired(); }

    @PostConstruct
    protected void postConstruct() {
      defaults();
    }

    private final void defaults() {
      Optional.ofNullable(enabled).ifPresentOrElse((x) -> {}, () -> SavageReflection.set(this, "enabled", true));
      Optional.ofNullable(gatewayEnabled).ifPresentOrElse((x) -> {}, () -> SavageReflection.set(this, "gatewayEnabled", false));
      Optional.ofNullable(StringUtils.defaultIfBlank(loginUrl, null)).ifPresentOrElse((x) -> {}, () -> SavageReflection.set(this, "loginUrl", "/login"));
      Optional.ofNullable(StringUtils.defaultIfBlank(loginProcessingUrl, null)).ifPresentOrElse((x) -> {}, () -> SavageReflection.set(this, "loginProcessingUrl", loginUrl));
      Optional.ofNullable(StringUtils.defaultIfBlank(loginFailureUrl, null)).ifPresentOrElse((x) -> {}, () -> SavageReflection.set(this, "loginFailureUrl", "/unauthorized"));
      Optional.ofNullable(StringUtils.defaultIfBlank(loginSuccessUrl, null)).ifPresentOrElse((x) -> {}, () -> SavageReflection.set(this, "loginSuccessUrl", "/home"));
      Optional.ofNullable(logoutConfirmRequired).ifPresentOrElse((x) -> {}, () -> SavageReflection.set(this, "logoutConfirmRequired", false));
      Optional.ofNullable(StringUtils.defaultIfBlank(logoutUrl, null)).ifPresentOrElse((x) -> {}, () -> SavageReflection.set(this, "logoutUrl", "/logout"));
      Optional.ofNullable(StringUtils.defaultIfBlank(logoutProcessingUrl, null)).ifPresentOrElse((x) -> {}, () -> SavageReflection.set(this, "logoutProcessingUrl", logoutUrl));
      Optional.ofNullable(StringUtils.defaultIfBlank(logoutSuccessUrl, null)).ifPresentOrElse((x) -> {}, () -> SavageReflection.set(this, "logoutSuccessUrl", gatewayEnabled ? "/" : loginUrl));
      Optional.ofNullable(StringUtils.defaultIfBlank(sessionExpiredUrl, null)).ifPresentOrElse((x) -> {}, () -> SavageReflection.set(this, "sessionExpiredUrl", "/expired"));
      Optional.ofNullable(StringUtils.defaultIfBlank(passwordParameter, null)).ifPresentOrElse((x) -> {}, () -> SavageReflection.set(this, "passwordParameter", "password"));
      Optional.ofNullable(StringUtils.defaultIfBlank(usernameParameter, null)).ifPresentOrElse((x) -> {}, () -> SavageReflection.set(this, "usernameParameter", "username"));
      SavageReflection.set(this, "anonymouslyAccessibles", Stream.of(
          Stream.of(
              "/*.ico"
            , "/api/public/**"
            , "/css/**"
            , "/error/**"
            , "/img/**"
            , "/js/**"
            , "/libs/**"
            , "/webjars/**"
          )
        , Stream.of("/accountExpired", "/accountLocked", "/credencialExpired", "/disabled", "/expired")
        , Optional.ofNullable(anonymouslyAccessibles).orElseGet(ArrayList::new).stream()
        , List.of(loginFailureUrl, gatewayEnabled ? "/" : "/".equals(logoutSuccessUrl) ? "" : logoutSuccessUrl).stream()
      ).flatMap((x) -> x).filter(StringUtils::isNotBlank).distinct().collect(Collectors.toUnmodifiableList()));
    }
  /* @formatter:on */}

  /**
   * OAuth 2.0 authentication .
   *
   * @author furplag
   *
   */
  @Immutable
  @ConstructorBinding
  @ConfigurationProperties(prefix = "project.boilerplate.security.o-auth2-login", ignoreInvalidFields = true, ignoreUnknownFields = true)
  @lombok.Value
  static class OAuth2LoginProperties {/* @formatter:off */

    /** if true, enable to Form login ( default: {@code true} ) . */ @Getter final Boolean enabled;

    /**
     * alias of {@link #getEnabled()} .
     *
     * @return {@link #enabled}
     */
    public boolean isEnabled() { return enabled; }

    @PostConstruct
    protected void postConstruct() {
      defaults();
    }

    private final void defaults() {
      Optional.ofNullable(enabled).ifPresentOrElse((x) -> {}, () -> SavageReflection.set(this, "enabled", false));
    }
  /* @formatter:on */}
}
