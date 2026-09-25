require 'rails_helper'

# Route walk: in SSO mode every credential-looking route must be denied by SsoMode::LocalCredentialGuard
# or be on a reviewed list. A new credential-looking route that is neither fails this spec.
RSpec.describe 'SSO local credential guard route walk' do
  allowed_routes = [['GET', '/auth/validate_token'], ['DELETE', '/auth/sign_out']].freeze
  credential_looking = /password|confirm|sign_in|sign_up|saml|omniauth|mfa|login|onboarding|token/

  # Reviewed exceptions: credential-looking route paths that are deliberately not denied, with the reason.
  reviewed_exceptions = {
    %r{\A/super_admin(/|\z)} => 'super admin devise scope and its actions: a separate credential universe, not the agent SSO lookup',
    %r{\A/auth/validate_token\z} => 'allowlisted: silent re-establishment of an expired app session',
    %r{/reset_access_token\z} => 'authenticated: rotates an API access token, not a login',
    %r{\A/platform/api/v1/users/:id/token\z} => 'PlatformApp bearer token endpoint, not a user login',
    %r{/whatsapp_business_management_token\z} => 'authenticated inbox setting',
    %r{/rotate_hmac_token\z} => 'authenticated inbox setting',
    %r{/conference/token\z} => 'authenticated video-call token',
    %r{\A/webhooks/telegram/:bot_token\z} => 'inbound webhook keyed by the bot token',
    %r{\A/rails/active_storage/disk/:encoded_token\z} => 'Active Storage signed upload URL',
    %r{/accounts/:account_id/onboarding} => 'post-login account onboarding steps, not the installation onboarding',
    %r{/accounts/:account_id/saml_settings\z} => 'authenticated admin configuration; SAML login itself is denied by the guard'
  }.freeze

  # Local-credential controller#action pairs that must each be reachable only as denied routes.
  local_credential_actions = %w[
    devise_overrides/sessions#create devise_overrides/passwords#create devise_overrides/passwords#update devise_overrides/passwords#edit
    devise_overrides/confirmations#show devise_overrides/confirmations#create devise_token_auth/registrations#create
    devise_token_auth/registrations#update devise_token_auth/registrations#destroy devise_overrides/omniauth_callbacks#omniauth_success
    auth/resend_confirmations#create installation/onboarding#index installation/onboarding#create api/v1/accounts#create
    api/v2/accounts#create api/v1/profiles#resend_confirmation api/v1/profile/mfa#show api/v1/profile/mfa#create
    api/v1/profile/mfa#destroy api/v1/profile/mfa#verify api/v1/profile/mfa#backup_codes platform/api/v1/users#login api/v1/auth#saml_login
  ].freeze

  let(:guard) { SsoMode::LocalCredentialGuard.new(->(_env) { [200, {}, ['passed']] }) }
  let(:all_routes) { Rails.application.routes.routes.reject { |r| r.path.spec.to_s.start_with?('/rails/info') } }

  around { |example| with_modified_env('AUTH_TYPE' => 'SSO', 'SSO_ACCOUNT_ID' => '1', 'SMB_NAME' => 'chat') { example.run } }

  def sample_paths(route)
    path = route.path.spec.to_s.sub('(.:format)', '')
    sample = path.gsub(/:[a-z_]+/, '1').gsub(/\*[a-z_]+/, 'x')
    verbs = route.verb.presence ? route.verb.split('|') : ['GET']
    verbs.map { |verb| [verb, sample, path] }
  end

  def denied?(verb, sample)
    env = Rack::MockRequest.env_for('/', method: verb)
    env['PATH_INFO'] = sample
    guard.call(env).first == 403
  end

  # Routes the guard lets through, as [route, verb, path], excluding the two allowlisted requests.
  def open_routes(list, allowed)
    list.flat_map do |route|
      sample_paths(route).filter_map do |verb, sample, path|
        [route, verb, path] unless allowed.include?([verb, sample]) || denied?(verb, sample)
      end
    end
  end

  it 'denies every route under /auth or /omniauth unless allowlisted' do
    scoped = all_routes.select { |r| r.path.spec.to_s.match?(%r{\A/(auth|omniauth)(/|\(|\z)}) }
    expect(scoped).not_to be_empty
    expect(open_routes(scoped, allowed_routes).map { |_, verb, path| "#{verb} #{path}" }).to eq([])
  end

  it 'denies or allowlists every route whose controller descends from DeviseController (super admin scope is reviewed)' do
    devise_routes = all_routes.select do |r|
      controller = r.defaults[:controller]
      controller && "#{controller.camelize}Controller".safe_constantize.try(:<, DeviseController)
    end
    expect(devise_routes).not_to be_empty
    leaks = open_routes(devise_routes, allowed_routes).reject { |_, _, path| reviewed_exceptions.keys.any? { |re| path.match?(re) } }
    expect(leaks.map { |route, verb, path| "#{verb} #{path} (#{route.defaults[:controller]})" }).to eq([])
  end

  it 'denies every credential-looking route or lists it as a reviewed exception' do
    candidates = all_routes.select { |r| r.path.spec.to_s.match?(credential_looking) }
    expect(candidates.size).to be > 20
    leaks = open_routes(candidates, allowed_routes).reject { |_, _, path| reviewed_exceptions.keys.any? { |re| path.match?(re) } }
    expect(leaks.map { |route, verb, path| "#{verb} #{path} (#{route.defaults[:controller]}##{route.defaults[:action]})" }).to eq([])
  end

  it 'keeps every reviewed exception pointing at a real route (no stale entries)' do
    paths = all_routes.flat_map { |r| sample_paths(r).map(&:last) }
    enterprise_only = [%r{/accounts/:account_id/saml_settings\z}, %r{/conference/token\z}] # routes absent in the FOSS build
    stale = reviewed_exceptions.keys.reject { |pattern| enterprise_only.include?(pattern) || paths.any? { |path| path.match?(pattern) } }
    expect(stale).to eq([])
  end

  it 'denies every explicitly listed local-credential controller#action' do
    local_credential_actions.each do |target|
      controller, action = target.split('#')
      matching = all_routes.select { |r| r.defaults[:controller] == controller && r.defaults[:action] == action }
      expect(matching).not_to be_empty, "no route for #{target}"
      leaks = open_routes(matching, allowed_routes)
      expect(leaks.map { |_, verb, path| "#{verb} #{path}" }).to eq([]), "#{target} is reachable"
    end
  end

  it 'does not deny the non-credential routes it must leave alone' do
    [['GET', '/health'], ['POST', '/proxy_auth/session'], ['PUT', '/api/v1/profile'], ['GET', '/api/v1/accounts/1'],
     ['GET', '/super_admin/sign_in'], ['GET', '/super_admin/logout']].each do |verb, path|
      expect(denied?(verb, path)).to be(false), "#{verb} #{path} should pass"
    end
  end
end
