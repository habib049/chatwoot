require 'rails_helper'
require 'open3'

# Preflight: one example per framework assumption the SSO plan relies on. Each name starts with the assumption id.
RSpec.describe 'SSO plan assumptions' do # rubocop:disable RSpec/DescribeClass
  it 'A1: Devise and devise_token_auth controllers inherit ApplicationController' do
    [DeviseOverrides::SessionsController, DeviseOverrides::PasswordsController, DeviseOverrides::ConfirmationsController,
     DeviseOverrides::TokenValidationsController, DeviseOverrides::OmniauthCallbacksController,
     DeviseTokenAuth::RegistrationsController].each do |klass|
      expect(klass.ancestors).to include(ApplicationController), "#{klass} does not inherit ApplicationController"
    end
  end

  it 'A2: the DTA default mount includes registrations, validate_token and sign_out' do
    routes = Rails.application.routes.routes.map { |r| [r.verb.to_s, r.path.spec.to_s.sub('(.:format)', '')] }
    expect(routes).to include(['GET', '/auth/validate_token'], ['DELETE', '/auth/sign_out'], ['POST', '/auth/sign_in'])
    %w[POST PUT DELETE].each { |verb| expect(routes).to include([verb, '/auth']) }
    controllers = Rails.application.routes.routes.select { |r| r.path.spec.to_s.start_with?('/auth') }.filter_map { |r| r.defaults[:controller] }
    expect(controllers).to include('devise_token_auth/registrations')
  end

  # DISPROVED as written: the OmniAuth path prefix is /omniauth (devise_token_auth sets it), not /auth.
  # Provider request URLs still live under /auth (routes mounted at 'auth'), callbacks under /omniauth, so both prefixes are live.
  describe 'A3: OmniAuth path prefix', type: :request do
    it 'is /omniauth, and provider paths exist under both /auth and /omniauth' do
      expect(OmniAuth.config.path_prefix).to eq('/omniauth')
      expect(Rails.application.middleware.map(&:name)).to include('OmniAuth::Builder')
      get '/auth/google_oauth2'
      expect(response).not_to have_http_status(:not_found)
      get '/omniauth/saml/callback'
      expect(response).not_to have_http_status(:not_found)
    end
  end

  describe 'A4: token expiry', type: :request do
    let(:user) { create(:user) }

    it 'sets expiry to now + token_lifespan and emits headers from an after_action' do
      freeze_time do
        headers = user.create_new_auth_token
        expect(headers['expiry'].to_i).to eq((Time.zone.now + DeviseTokenAuth.token_lifespan).to_i)
      end
      after_actions = DeviseTokenAuth::Concerns::SetUserByToken.instance_method(:update_auth_header)
      expect(after_actions).to be_present
      callbacks = ApplicationController._process_action_callbacks.select { |c| c.kind == :after }.map(&:filter)
      expect(callbacks).to include(:update_auth_header)
    end

    it 'keeps the expiry absolute across requests because headers do not change on each request' do
      expect(DeviseTokenAuth.change_headers_on_each_request).to be false
      headers = user.create_new_auth_token
      expiry = user.reload.tokens[headers['client']]['expiry']
      get '/auth/validate_token', headers: headers
      expect(response).to have_http_status(:ok)
      expect(user.reload.tokens[headers['client']]['expiry']).to eq(expiry)
    end
  end

  describe 'A5: current_user with invalid or expired tokens', type: :controller do
    let(:user) { create(:user) }

    controller(ApplicationController) do
      def index
        render json: { user_id: current_user&.id }
      end
    end

    it 'returns nil without raising and without changing stored tokens' do
      headers = user.create_new_auth_token
      before = user.reload.tokens.deep_dup

      request.headers.merge!(headers.merge('access-token' => 'not-a-token'))
      get :index
      expect(response.parsed_body['user_id']).to be_nil

      expired = user.reload.tokens.deep_dup
      expired[headers['client']]['expiry'] = 1.minute.ago.to_i
      user.update_column(:tokens, expired) # rubocop:disable Rails/SkipsModelValidations -- a normal save prunes expired tokens
      request.headers.merge!(headers)
      get :index
      expect(response.parsed_body['user_id']).to be_nil
      expect(user.reload.tokens).to eq(expired)
      expect(before.keys).to eq(expired.keys)
    end
  end

  describe 'A6: duplicate email on User' do
    it 'raises RecordInvalid on create! and RecordNotUnique when validations are skipped' do
      existing = create(:user)
      expect { create(:user, email: existing.email) }.to raise_error(ActiveRecord::RecordInvalid)
      expect do
        User.transaction(requires_new: true) { build(:user, email: existing.email).save!(validate: false) }
      end.to raise_error(ActiveRecord::RecordNotUnique)
    end
  end

  it 'A7: Rack::Utils.unescape_path does not raise on invalid % sequences but can return invalid UTF-8' do
    expect(Rack::Utils.unescape_path('/a/%zz')).to eq('/a/%zz')
    expect(Rack::Utils.unescape_path('/a/%')).to eq('/a/%')
    expect(Rack::Utils.unescape_path('/a/%2')).to eq('/a/%2')
    bad = Rack::Utils.unescape_path('/auth/%ff')
    expect(bad.valid_encoding?).to be false
    expect { bad.downcase }.to raise_error(ArgumentError)
  end

  it 'A8: vitest accepts a positional file filter after pnpm test' do
    spec = 'app/javascript/shared/helpers/specs/timeHelper.spec.js'
    out, status = Open3.capture2e('pnpm', 'test', spec, chdir: Rails.root.to_s)
    expect(status).to be_success, out
    expect(out).to match(/Test Files\s+1 passed \(1\)/)
  end

  describe 'A9: controller cookies', type: :controller do
    controller(ApplicationController) do
      def index
        cookies.delete('cw_d_session_info', path: '/')
        head :ok
      end
    end

    it 'A9: cookies.delete with path / yields a Set-Cookie that expires the JS-set cookie' do
      request.cookies['cw_d_session_info'] = 'x' # Rails only emits a deletion when the request carried the cookie
      get :index
      set_cookie = response.headers['Set-Cookie']
      expect(set_cookie).to include('cw_d_session_info=;')
      expect(set_cookie).to match(%r{path=/}i)
      expect(set_cookie).to match(/expires=Thu, 01 (Jan|Jan) 1970/i)
    end
  end

  it 'A10: prepend_before_action in ApplicationController runs before the DTA callbacks' do
    parent = Class.new(ApplicationController) { prepend_before_action :sso_first }
    child = Class.new(parent) { before_action :child_action }
    [parent, child].each do |klass|
      filters = klass._process_action_callbacks.select { |c| c.kind == :before }.map(&:filter)
      expect(filters.first).to eq(:sso_first)
      expect(filters.index(:sso_first)).to be < filters.index(:set_request_start)
    end
  end
end
