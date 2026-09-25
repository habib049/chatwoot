require 'rails_helper'

RSpec.describe 'SSO local credential guard', type: :request do
  let(:sso_env) { { 'AUTH_TYPE' => 'SSO', 'SSO_ACCOUNT_ID' => '1', 'SMB_NAME' => 'chat' } }
  let(:denied_body) { { 'error' => 'Local credential login is disabled', 'error_code' => 'sso_local_auth_disabled' } }

  def expect_denied
    expect(response).to have_http_status(:forbidden)
    expect(response.media_type).to eq('application/json')
    expect(response.parsed_body).to eq(denied_body)
  end

  def expect_not_denied
    expect(response.body).not_to include('sso_local_auth_disabled')
  end

  context 'when SSO mode is off' do
    it 'passes every request through untouched' do
      post '/auth/sign_in', params: { email: 'nobody@example.com', password: 'wrong' }
      expect(response).to have_http_status(:unauthorized)
      expect_not_denied

      post '/api/v1/accounts', params: { email: 'a@example.com' }
      expect_not_denied

      get '/installation/onboarding'
      expect_not_denied
      get '/auth/validate_token'
      expect_not_denied
      post '/resend_confirmation', params: { email: 'a@example.com' }
      expect_not_denied
    end

    it 'ignores a malformed SSO config and even AUTH_TYPE=SSO lookalikes only fail at boot, not per request' do
      with_modified_env('AUTH_TYPE' => nil) do
        get '/auth/google_oauth2'
        expect_not_denied
      end
    end
  end

  context 'when SSO mode is on' do
    around { |example| with_modified_env(sso_env) { example.run } }

    it 'denies POST /auth/sign_in' do
      post '/auth/sign_in', params: { email: 'a@example.com', password: 'x' }
      expect_denied
    end

    it 'denies sign_in variants: credentials in headers, mfa_token and sso_auth_token' do
      post '/auth/sign_in', headers: { 'email' => 'a@example.com', 'password' => 'x' }
      expect_denied
      post '/auth/sign_in', params: { mfa_token: 'x', otp_code: '1' }
      expect_denied
      post '/auth/sign_in', params: { sso_auth_token: 'x', email: 'a@example.com' }
      expect_denied
    end

    [
      ['GET', '/auth/sign_in'], ['POST', '/auth/password'], ['PUT', '/auth/password'], ['GET', '/auth/password/edit'],
      ['POST', '/auth/confirmation'], ['GET', '/auth/confirmation'], ['POST', '/auth'], ['PUT', '/auth'], ['DELETE', '/auth'],
      ['GET', '/auth'], ['GET', '/auth/google_oauth2'], ['POST', '/auth/google_oauth2'], ['GET', '/auth/google_oauth2/callback'],
      ['GET', '/auth/saml'], ['POST', '/auth/saml'], ['GET', '/omniauth/google_oauth2/callback'], ['GET', '/omniauth/saml/callback'],
      ['POST', '/omniauth/saml/callback'], ['GET', '/omniauth'], ['GET', '/auth/anything/else'],
      ['POST', '/resend_confirmation'], ['GET', '/resend_confirmation'], ['POST', '/api/v1/auth/saml_login'], ['GET', '/api/v1/auth/saml_login'],
      ['POST', '/api/v1/accounts'], ['POST', '/api/v2/accounts'], ['GET', '/installation/onboarding'], ['POST', '/installation/onboarding'],
      ['POST', '/api/v1/profile/resend_confirmation'], ['GET', '/api/v1/profile/mfa'], ['POST', '/api/v1/profile/mfa'],
      ['DELETE', '/api/v1/profile/mfa'], ['POST', '/api/v1/profile/mfa/verify'], ['POST', '/api/v1/profile/mfa/backup_codes'],
      ['GET', '/platform/api/v1/users/1/login'], ['GET', '/platform/api/v1/users/abc/login'], ['POST', '/api/v1/accounts.json'],
      ['POST', '/api/v1/accounts/']
    ].each do |verb, path|
      it "denies #{verb} #{path}" do
        process(verb.downcase.to_sym, path)
        expect_denied
      end
    end

    ['/auth/sign_in.json', '/auth/sign_in/', '//auth/sign_in', '/AUTH/sign_in', '/%61uth/sign_in', '/auth/sign_in.json/', '/Auth//Sign_In.JSON',
     '/auth%2fsign_in', '/auth/sign_in%2ejson'].each do |path|
      it "denies the path variant #{path}" do
        post path, params: { email: 'a@example.com', password: 'x' }
        expect_denied
      end
    end

    context 'when the path cannot be decoded' do
      let(:app) { ->(_env) { [200, {}, ['passed']] } }
      let(:guard) { SsoMode::LocalCredentialGuard.new(app) }

      def call_guard(path, method: 'GET')
        env = Rack::MockRequest.env_for('/', method: method)
        env['PATH_INFO'] = path
        guard.call(env)
      end

      it 'falls back to the raw path when percent-decoding raises and still denies under a denied prefix' do
        allow(Rack::Utils).to receive(:unescape_path).and_raise(ArgumentError)
        expect(call_guard('/auth/sign_in', method: 'POST').first).to eq(403)
        expect(call_guard('/health').first).to eq(200)
      end

      it 'denies invalid percent sequences under a denied prefix, including ones that decode to invalid UTF-8' do
        %w[/auth/%zz /auth/%ff /auth/sign_in%e4%zz /auth/% /omniauth/%c3%28].each do |path|
          expect(call_guard(path).first).to eq(403), "expected #{path} to be denied"
        end
      end

      it 'passes an undecodable path outside the denied set' do
        expect(call_guard('/foo/%ff').first).to eq(200)
      end

      it 'returns the static JSON body' do
        status, headers, body = call_guard('/auth/sign_in', method: 'POST')
        expect(status).to eq(403)
        expect(headers['Content-Type']).to eq('application/json')
        expect(JSON.parse(body.join)).to eq(denied_body)
      end
    end

    it 'allows GET /auth/validate_token and DELETE /auth/sign_out' do
      get '/auth/validate_token'
      expect_not_denied
      delete '/auth/sign_out'
      expect_not_denied
    end

    it 'allows the two exempt requests in path variants, since they normalise to the same exact path' do
      get '/auth/validate_token.json'
      expect_not_denied
      delete '/auth/sign_out/'
      expect_not_denied
    end

    it 'denies validate_token and sign_out under any other method or override' do
      post '/auth/validate_token'
      expect_denied
      get '/auth/sign_out'
      expect_denied
      post '/auth/sign_out', params: { _method: 'DELETE' }
      expect_denied
      post '/auth/sign_out', headers: { 'X-HTTP-Method-Override' => 'DELETE' }
      expect_denied
      delete '/auth/password'
      expect_denied
      delete '/auth/validate_token'
      expect_denied
      get '/auth/validate_token/extra'
      expect_denied
    end

    it 'does not deny neighbouring paths that are not local credential surfaces' do
      account = create(:account)
      user = create(:user, account: account)
      get "/api/v1/accounts/#{account.id}", headers: user.create_new_auth_token
      expect_not_denied
      expect(response).to have_http_status(:success)

      put '/api/v1/profile', params: { profile: { name: 'New' } }, headers: user.create_new_auth_token, as: :json
      expect_not_denied

      get '/super_admin/sign_in'
      expect_not_denied
      get '/health'
      expect(response).to have_http_status(:success)
      post '/proxy_auth/session'
      expect_not_denied
      get '/platform/api/v1/users/1'
      expect_not_denied
      get '/authors'
      expect_not_denied
      get '/api/v1/accounts' # GET is not the signup route
      expect_not_denied
      get '/api/v1/profile/mfa_status'
      expect_not_denied
    end

    it 'denies Google OAuth even when ENABLE_GOOGLE_OAUTH_LOGIN is true in the installation config' do
      InstallationConfig.where(name: 'ENABLE_GOOGLE_OAUTH_LOGIN').delete_all
      InstallationConfig.create!(name: 'ENABLE_GOOGLE_OAUTH_LOGIN', serialized_value: { value: true }.with_indifferent_access)
      GlobalConfig.clear_cache
      get '/auth/google_oauth2'
      expect_denied
      get '/auth/google_oauth2/callback'
      expect_denied
    ensure
      GlobalConfig.clear_cache
    end
  end
end
