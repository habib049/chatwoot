# Fixes the stale-session-on-user-switch bug for API calls: when user A logs out of the portal and
# user B logs in, A's token is still valid in the browser. On every API request that carries DTA
# headers the proxy identity is compared with the token's user; on a mismatch that client's token is
# revoked and the request is answered with 401 before any action, Pundit or set_current_user runs.
module ProxyAuth::IdentityReconciliation
  extend ActiveSupport::Concern

  DTA_HEADERS = %w[access-token client uid].freeze
  SESSION_COOKIE = 'cw_d_session_info'.freeze

  included do
    prepend_before_action :reconcile_proxy_identity
  end

  private

  def reconcile_proxy_identity
    return unless reconcilable_request?

    user = current_user
    return render_reconcile_error('sso_session_required') if user.nil?
    return if identity_consistent?(user)

    revoke_client_token(user)
    render_reconcile_error('sso_identity_changed')
  end

  def reconcilable_request?
    return false unless SsoMode.enabled?
    # Super admin is a separate credential universe; the exemption is keyed on the server-known controller path.
    return false if controller_path.start_with?('super_admin/')

    # Nothing to reconcile without a DTA session; downstream authentication still applies.
    DTA_HEADERS.all? { |name| request.headers[name].is_a?(String) && request.headers[name].present? }
  end

  # An absent header is not a logout signal; only a usable, different identity or an unusable one flushes.
  def identity_consistent?(user)
    identity = ProxyAuth::Identity.from_request(request)
    identity.status == :absent || (identity.status == :present && user.email.to_s.strip.downcase == identity.email)
  end

  def revoke_client_token(user)
    client = request.headers['client']
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
