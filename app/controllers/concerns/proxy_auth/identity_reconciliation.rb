# Fixes the stale-session-on-user-switch bug for API calls: when user A logs out of the portal and
# user B logs in, A's token is still valid in the browser. On every API request the proxy identity is
# compared with whoever devise_token_auth authenticated (it accepts the token from the three headers,
# from query params and from a Bearer Authorization header, so the comparison is on the resolved user,
# never on one channel); on a mismatch that client's token is revoked and the request is answered with
# 401 before any action, Pundit or set_current_user runs.
module ProxyAuth::IdentityReconciliation
  extend ActiveSupport::Concern

  DTA_HEADERS = %w[access-token client uid].freeze
  SESSION_COOKIE = 'cw_d_session_info'.freeze

  private

  # Page loads: the shell holds no user data, so expiring a stale JS-readable session cookie is enough;
  # the SPA then finds no cookie and proxy-logs-in as the incoming identity. The cookie is client input.
  def reconcile_page_identity
    return unless SsoMode.enabled?

    raw = cookies[SESSION_COOKIE]
    return if raw.blank?

    cookies.delete(SESSION_COOKIE, path: '/') unless page_cookie_matches_identity?(raw)
  end

  def page_cookie_matches_identity?(raw)
    cookie = JSON.parse(raw, max_nesting: 5)
    uid = cookie['uid'] if cookie.is_a?(Hash)
    return false unless uid.is_a?(String)

    identity = ProxyAuth::Identity.from_request(request)
    identity.status == :absent || (identity.status == :present && uid.strip.downcase == identity.email)
  rescue StandardError
    false # unparsable, too deeply nested or wrongly typed: no usable session
  end

  def reconcile_proxy_identity
    return unless reconcilable_request?

    user = current_user
    # No usable DTA session: nothing to reconcile and downstream authentication still applies. Only the
    # three headers sent with a bad token get the explicit 401, as before.
    return render_reconcile_error('sso_session_required') if user.nil? && dta_headers_present?
    return if user.nil? || identity_consistent?(user)

    revoke_client_token(user)
    render_reconcile_error('sso_identity_changed')
  end

  def reconcilable_request?
    return false unless SsoMode.enabled?

    # Super admin is a separate credential universe; the exemption is keyed on the server-known controller path.
    !controller_path.start_with?('super_admin/')
  end

  def dta_headers_present?
    DTA_HEADERS.all? { |name| request.headers[name].is_a?(String) && request.headers[name].present? }
  end

  # An absent header is not a logout signal; only a usable, different identity or an unusable one flushes.
  def identity_consistent?(user)
    identity = ProxyAuth::Identity.from_request(request)
    identity.status == :absent || (identity.status == :present && user.email.to_s.strip.downcase == identity.email)
  end

  # The client DTA accepted, wherever it came from (@token is DTA's own record of it); the header is only a
  # fallback so a request that authenticated by header revokes exactly what it always did.
  def revoke_client_token(user)
    client = @token&.client.presence || request.headers['client']
    user.with_lock do
      user.tokens.delete(client)
      user.save!(validate: false)
    end
  end

  def render_reconcile_error(error_code)
    cookies.delete(SESSION_COOKIE, path: '/')
    render json: { error: 'Session is no longer valid', error_code: error_code }, status: :unauthorized
  end
end
