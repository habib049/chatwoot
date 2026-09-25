# In SSO mode the proxy identity is the only way in, so every local-credential surface is refused
# server-side. Sits first in the Rack stack, ahead of OmniAuth (which handles /auth/* before the
# router). Keys only off SsoMode.enabled? (ENV), so DB-backed ENABLE_* flags and SAML rows cannot
# keep a login open. Has no dependency on enterprise/.
class SsoMode::LocalCredentialGuard
  DENIED_BODY = { error: 'Local credential login is disabled', error_code: 'sso_local_auth_disabled' }.to_json.freeze
  DENIED_PREFIXES = %w[/auth /omniauth /api/v1/profile/mfa].freeze
  ALLOWED = [['GET', '/auth/validate_token'], ['DELETE', '/auth/sign_out']].freeze
  DENIED_PATHS = %w[/resend_confirmation /api/v1/auth/saml_login /installation/onboarding].freeze
  DENIED_POSTS = %w[/api/v1/accounts /api/v2/accounts /api/v1/profile/resend_confirmation].freeze
  PLATFORM_LOGIN = %r{\A/platform/api/v1/users/[^/]+/login\z}

  def initialize(app)
    @app = app
  end

  def call(env)
    return @app.call(env) unless SsoMode.enabled?

    denied?(env['REQUEST_METHOD'].to_s, self.class.normalise(env['PATH_INFO'])) ? deny : @app.call(env)
  rescue StandardError
    deny # fail closed: no 500 path
  end

  # Percent-decode once, then lowercase, squeeze //, drop a trailing / and a final .ext, so every
  # alias the router or OmniAuth accepts lands on the canonical path (a superset of what they match).
  def self.normalise(raw)
    utf8 = raw.to_s.dup.force_encoding(Encoding::UTF_8)
    path = begin
      Rack::Utils.unescape_path(utf8)
    rescue StandardError
      utf8
    end
    path = path.scrub.downcase.squeeze('/').delete_suffix('/') # unescape_path can yield invalid UTF-8 (assumption A7)
    dot = path.rindex('.')
    dot && dot > path.rindex('/').to_i ? path[0...dot] : path
  end

  private

  def denied?(method, path)
    return false if ALLOWED.include?([method, path])

    denied_path?(path) || (method == 'POST' && DENIED_POSTS.include?(path))
  end

  def denied_path?(path)
    DENIED_PREFIXES.any? { |prefix| path == prefix || path.start_with?("#{prefix}/") } ||
      DENIED_PATHS.include?(path) || path.match?(PLATFORM_LOGIN)
  end

  def deny
    [403, { 'Content-Type' => 'application/json', 'Content-Length' => DENIED_BODY.bytesize.to_s }, [DENIED_BODY]]
  end
end

Rails.application.config.middleware.insert_before(0, SsoMode::LocalCredentialGuard)
