require 'rails_helper'

RSpec.describe 'ProxyAuth identity reconciliation', type: :request do
  let(:account) { create(:account) }
  let(:user) { create(:user, email: 'alice@example.com', password: 'Test123!', account: account, role: :agent) }
  let(:sso_env) { { 'AUTH_TYPE' => 'SSO', 'SSO_ACCOUNT_ID' => account.id.to_s, 'SMB_NAME' => 'chat', 'SSO_TRUSTED_PROXY_CIDRS' => nil } }
  let!(:auth) { user.create_new_auth_token }
  let(:client) { auth['client'] }

  around { |example| with_modified_env(sso_env) { example.run } }

  def call_profile(headers = auth, proxy_email: :none)
    headers = headers.merge('X-Auth-Request-Email' => proxy_email) unless proxy_email == :none
    get '/api/v1/profile', headers: headers
  end

  def expect_flushed(error_code)
    expect(response).to have_http_status(:unauthorized)
    expect(response.parsed_body['error_code']).to eq(error_code)
    expect(response.parsed_body.keys).to contain_exactly('error', 'error_code')
    expect(Array(response.headers['Set-Cookie']).join("\n")).to match(/cw_d_session_info=;.*expires=Thu, 01 Jan 1970/i)
  end

  before { cookies['cw_d_session_info'] = 'stale' }

  describe 'when the identity matches or is absent' do
    ['alice@example.com', '  ALICE@example.com  ', 'Alice@EXAMPLE.COM'].each do |header|
      it "passes through for header #{header.inspect}" do
        call_profile(proxy_email: header)
        expect(response).to have_http_status(:success)
        expect(response.parsed_body['email']).to eq('alice@example.com')
      end
    end

    it 'normalises the session user email as well as the header' do
      user.update_column(:email, 'Alice@Example.com') # rubocop:disable Rails/SkipsModelValidations
      call_profile(proxy_email: '  ALICE@example.com  ')
      expect(response).to have_http_status(:success)
    end

    it 'passes through when the header is absent' do
      call_profile
      expect(response).to have_http_status(:success)
    end

    it 'passes through when the header is whitespace only' do
      call_profile(proxy_email: '   ')
      expect(response).to have_http_status(:success)
    end

    it 'passes through when the header is empty' do
      call_profile(proxy_email: '')
      expect(response).to have_http_status(:success)
    end
  end

  describe 'on identity mismatch' do
    it 'revokes the token, drops the UserSession, expires the cookie and returns 401 sso_identity_changed' do
      user.user_sessions.create!(client_id: client)
      expect(user.reload.tokens).to have_key(client)

      call_profile(proxy_email: 'bob@example.com')

      expect_flushed('sso_identity_changed')
      expect(user.reload.tokens).not_to have_key(client)
      expect(user.user_sessions.where(client_id: client)).to be_empty
      expect(response.body).not_to include('alice')
    end

    it 'does not run the action, so a state-changing request has no effect' do
      put '/api/v1/profile', params: { profile: { name: 'Changed By Old Session' } },
                             headers: auth.merge('X-Auth-Request-Email' => 'bob@example.com'), as: :json

      expect_flushed('sso_identity_changed')
      expect(user.reload.name).not_to eq('Changed By Old Session')
    end

    it 'runs before set_current_user' do
      filters = ApplicationController._process_action_callbacks.select { |c| c.kind == :before }.map(&:filter)
      expect(filters.index(:reconcile_proxy_identity)).to be < filters.index(:set_current_user)
      expect(filters.index(:reconcile_proxy_identity)).to be < filters.index(:set_request_start)
    end

    it 'leaves the same user other clients untouched' do
      other = user.create_new_auth_token
      call_profile(proxy_email: 'bob@example.com')

      expect(user.reload.tokens.keys).to eq([other['client']])
      get '/api/v1/profile', headers: other.merge('X-Auth-Request-Email' => 'alice@example.com')
      expect(response).to have_http_status(:success)
    end

    it 'is idempotent when the same client is revoked twice' do
      call_profile(proxy_email: 'bob@example.com')
      expect_flushed('sso_identity_changed')

      cookies['cw_d_session_info'] = 'stale' # the first response deleted it from the jar
      call_profile(proxy_email: 'bob@example.com')
      expect_flushed('sso_session_required')
      expect(user.reload.tokens).not_to have_key(client)
    end

    [
      'a b@example.com', 'a@b@example.com', 'v%@example.com', 'not-an-email', "a\u0001b@example.com", 'alicé@example.com'
    ].each do |header|
      it "flushes the session for the unusable header #{header.inspect}" do
        call_profile(proxy_email: header)
        expect_flushed('sso_identity_changed')
        expect(user.reload.tokens).not_to have_key(client)
      end
    end

    it 'treats a bare username as a mismatch when no DEFAULT_EMAIL_DOMAIN is set' do
      call_profile(proxy_email: 'alice')
      expect_flushed('sso_identity_changed')
    end

    it 'treats a bare username as a match when it synthesises to the session email' do
      with_modified_env('DEFAULT_EMAIL_DOMAIN' => 'example.com') do
        call_profile(proxy_email: 'alice')
        expect(response).to have_http_status(:success)
      end
    end
  end

  describe 'with an invalid or expired token' do
    it 'returns 401 sso_session_required, expires the cookie and revokes nothing for an expired token' do
      tokens = user.reload.tokens.deep_dup
      tokens[client]['expiry'] = 1.minute.ago.to_i
      user.update_column(:tokens, tokens) # rubocop:disable Rails/SkipsModelValidations

      call_profile(proxy_email: 'bob@example.com')

      expect_flushed('sso_session_required')
      expect(user.reload.tokens).to eq(tokens)
    end

    it 'revokes nothing for a forged uid and client with a bad token' do
      before = user.reload.tokens.deep_dup
      forged = { 'access-token' => 'forged', 'client' => client, 'uid' => user.uid, 'token-type' => 'Bearer' }

      call_profile(forged, proxy_email: 'bob@example.com')

      expect_flushed('sso_session_required')
      expect(user.reload.tokens).to eq(before)
    end
  end

  describe 'endpoints it applies to' do
    it 'applies on GET /auth/validate_token' do
      get '/auth/validate_token', headers: auth.merge('X-Auth-Request-Email' => 'bob@example.com')
      expect_flushed('sso_identity_changed')
    end

    it 'applies on PUT /api/v1/profile' do
      put '/api/v1/profile', params: { profile: { name: 'x' } }, headers: auth.merge('X-Auth-Request-Email' => 'bob@example.com'), as: :json
      expect_flushed('sso_identity_changed')
    end

    it 'applies on an account-scoped API call' do
      get "/api/v1/accounts/#{account.id}", headers: auth.merge('X-Auth-Request-Email' => 'bob@example.com')
      expect_flushed('sso_identity_changed')
    end

    it 'still lets a matching identity through on validate_token and account-scoped calls' do
      get '/auth/validate_token', headers: auth.merge('X-Auth-Request-Email' => 'alice@example.com')
      expect(response).to have_http_status(:success)
      get "/api/v1/accounts/#{account.id}", headers: auth.merge('X-Auth-Request-Email' => 'alice@example.com')
      expect(response).to have_http_status(:success)
    end
  end

  describe 'exemptions' do
    it 'skips only controllers whose path starts with super_admin/' do
      controller = ApplicationController.new
      # ponytail: exercises the concern directly; a real super admin controller does not inherit ApplicationController
      allow(controller).to receive(:controller_path).and_return('super_admin/accounts')
      allow(controller).to receive(:request).and_return(instance_double(ActionDispatch::Request))
      expect(controller.send(:reconcile_proxy_identity)).to be_nil
    end

    %w[api/v1/super_admin_things foo/super_admin/bar super_admin].each do |path|
      it "does not skip the controller path #{path}" do
        controller = ApplicationController.new
        allow(controller).to receive(:controller_path).and_return(path)
        request = instance_double(ActionDispatch::Request, headers: {})
        allow(controller).to receive(:request).and_return(request)
        expect(request).to receive(:headers).at_least(:once).and_return({})
        controller.send(:reconcile_proxy_identity)
      end
    end

    it 'does not reconcile a real super admin page even with a mismatching identity' do
      get '/super_admin/sign_in', headers: auth.merge('X-Auth-Request-Email' => 'bob@example.com')

      expect(response.body).not_to include('sso_')
      expect(user.reload.tokens).to have_key(client)
    end

    it 'leaves an api_access_token-only request untouched' do
      call_with = { 'api_access_token' => user.access_token.token, 'X-Auth-Request-Email' => 'bob@example.com' }
      get '/api/v1/profile', headers: call_with

      expect(response).to have_http_status(:success)
      expect(user.reload.tokens).to have_key(client)
    end

    blank_values = ['', '   ', :omit]
    %w[access-token client uid].each do |missing|
      blank_values.each do |value|
        it "leaves the request untouched when #{missing} is #{value == :omit ? 'missing' : value.inspect}" do
          headers = auth.merge('X-Auth-Request-Email' => 'bob@example.com')
          value == :omit ? headers.delete(missing) : headers[missing] = value

          get '/api/v1/profile', headers: headers

          expect(response.body).not_to include('sso_')
          expect(user.reload.tokens).to have_key(client)
        end
      end
    end
  end

  describe 'with SSO mode unset' do
    around { |example| with_modified_env('AUTH_TYPE' => nil) { example.run } }

    it 'does not change any response for a mismatching proxy header' do
      call_profile(proxy_email: 'bob@example.com')

      expect(response).to have_http_status(:success)
      expect(response.body).not_to include('sso_')
      expect(user.reload.tokens).to have_key(client)
    end
  end
end
