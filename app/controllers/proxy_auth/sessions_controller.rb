# SSO login: the identity comes only from the X-Auth-Request-Email header (set by the edge proxy),
# never from params. Issues a normal devise_token_auth token so Pundit, Current.* and Action Cable work unchanged.
class ProxyAuth::SessionsController < ApplicationController
  include AuthHelper

  before_action :ensure_sso_mode

  rescue_from ProxyAuth::Provisioner::AccountUnavailable do
    render_sso_error(:forbidden, 'sso_account_unavailable')
  end
  rescue_from ProxyAuth::Provisioner::LimitExceeded do
    render_sso_error(:payment_required, 'sso_agent_limit_reached')
  end
  rescue_from ProxyAuth::Provisioner::UserInactive do
    render_sso_error(:forbidden, 'sso_user_inactive')
  end

  def create
    identity = ProxyAuth::Identity.from_request(request)
    return render_sso_error(:unauthorized, 'sso_identity_missing') if identity.status == :absent
    return render_sso_error(:unauthorized, 'sso_identity_unusable') if identity.status == :unusable

    user = ProxyAuth::Provisioner.call(identity.email)
    send_auth_headers(user)
    sign_in(:user, user, store: false, bypass: false)
    track_user_session(user)
    render partial: 'devise/auth', formats: [:json], locals: { resource: user }
  end

  private

  def ensure_sso_mode
    head :not_found unless SsoMode.enabled?
  end

  def render_sso_error(status, error_code)
    render json: { error: 'SSO login failed', error_code: error_code }, status: status
  end

  def track_user_session(user)
    UserSessionTrackingService.new(user: user, request: request, client_id: response.headers['client']).create_or_update!
  rescue StandardError => e
    Rails.logger.warn "Session tracking failed: #{e.message}"
  end
end
