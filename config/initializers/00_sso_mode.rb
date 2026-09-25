# The one backend definition of "SSO mode". Reads only ENV, never GlobalConfig or the DB,
# so stored data cannot switch it. Every other file must call SsoMode.enabled?.
# Loaded before devise_token_auth.rb (00_ prefix); not Zeitwerk-managed.
require 'ipaddr'

module SsoMode
  class InvalidConfig < StandardError; end

  DEFAULT_LIFETIME_SECONDS = 604_800
  LIFETIME_RANGE = (60..31_536_000)
  LABEL = /\A[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\z/

  module_function

  def enabled?
    ENV['AUTH_TYPE'].to_s.strip == 'SSO'
  end

  # AUTH_TYPE that differs from SSO only by case is a typo that would silently leave local login open.
  # Then, in SSO mode, every SSO_* value is parsed so a malformed one aborts boot.
  def validate!
    auth_type = ENV['AUTH_TYPE'].to_s.strip
    raise InvalidConfig, "AUTH_TYPE must be exactly 'SSO' to enable SSO mode, got '#{auth_type}'" if auth_type.casecmp?('SSO') && auth_type != 'SSO'
    return unless enabled?

    session_lifetime_seconds
    account_id
    portal_name
    default_email_domain
    trusted_proxy_ranges
  end

  def session_lifetime_seconds
    raw = ENV.fetch('SESSION_COOKIE_MAX_AGE_SECONDS', nil)
    return DEFAULT_LIFETIME_SECONDS if raw.nil?

    seconds = raw.match?(/\A[0-9]{1,9}\z/) ? raw.to_i : nil
    unless seconds && LIFETIME_RANGE.cover?(seconds)
      raise InvalidConfig,
            "SESSION_COOKIE_MAX_AGE_SECONDS must be an integer in #{LIFETIME_RANGE}, got '#{raw}'"
    end

    seconds
  end

  def token_lifespan
    enabled? ? session_lifetime_seconds.seconds : 2.months
  end

  def account_id
    raw = required('SSO_ACCOUNT_ID')
    raise InvalidConfig, "SSO_ACCOUNT_ID must match [1-9][0-9]{0,9}, got '#{raw}'" unless raw.match?(/\A[1-9][0-9]{0,9}\z/)

    raw.to_i
  end

  def portal_name
    raw = required('SMB_NAME')
    raise InvalidConfig, "SMB_NAME must be a lowercase DNS label, got '#{raw}'" unless raw.match?(LABEL)

    raw
  end

  def default_email_domain
    raw = ENV.fetch('DEFAULT_EMAIL_DOMAIN', nil)
    return nil if raw.nil?

    labels = raw.split('.', -1)
    return raw if labels.size >= 2 && labels.all? { |label| label.match?(LABEL) }

    raise InvalidConfig, "DEFAULT_EMAIL_DOMAIN must be a lowercase domain with at least 2 labels, got '#{raw}'"
  end

  def trusted_proxy_ranges
    raw = ENV.fetch('SSO_TRUSTED_PROXY_CIDRS', nil)
    return [] if raw.nil?

    raise InvalidConfig, 'SSO_TRUSTED_PROXY_CIDRS is set but empty' if raw.empty?

    raw.split(',', -1).map { |entry| IPAddr.new(entry) }
  rescue ArgumentError => e # IPAddr::Error descends from ArgumentError
    raise InvalidConfig, "SSO_TRUSTED_PROXY_CIDRS has an invalid entry: #{e.message}"
  end

  def required(name)
    ENV.fetch(name) { raise InvalidConfig, "#{name} is required in SSO mode" }
  end
end

SsoMode.validate!
