require 'rails_helper'

RSpec.describe 'POST /proxy_auth/session', type: :request do
  let(:account) { create(:account) }
  let(:sso_env) { { 'AUTH_TYPE' => 'SSO', 'SSO_ACCOUNT_ID' => account.id.to_s, 'SMB_NAME' => 'chat', 'SSO_TRUSTED_PROXY_CIDRS' => nil } }
  let(:header) { { 'X-Auth-Request-Email' => 'alice@example.com' } }

  around { |example| with_modified_env(sso_env) { example.run } }

  def expect_error(status, code)
    expect(response).to have_http_status(status)
    expect(response.parsed_body['error_code']).to eq(code)
    %w[access-token client uid expiry].each { |h| expect(response.headers[h]).to be_nil }
  end

  it 'returns 401 sso_identity_missing without the header' do
    post '/proxy_auth/session'
    expect_error(401, 'sso_identity_missing')
  end

  it 'returns 401 sso_identity_missing for a whitespace-only header' do
    post '/proxy_auth/session', headers: { 'X-Auth-Request-Email' => '  ' }
    expect_error(401, 'sso_identity_missing')
  end

  ['a@b@c.com', '%@%.%', 'v%@example.com', 'a b@example.com', "#{'a' * 260}@example.com", 'plain'].each do |value|
    it "returns 401 sso_identity_unusable for #{value[0, 20].inspect}" do
      post '/proxy_auth/session', headers: { 'X-Auth-Request-Email' => value }
      expect_error(401, 'sso_identity_unusable')
    end
  end

  it 'issues access-token, client, uid and expiry headers and user JSON for a valid header' do
    post '/proxy_auth/session', headers: header

    expect(response).to have_http_status(:success)
    %w[access-token client uid expiry].each { |h| expect(response.headers[h]).to be_present }
    expect(response.headers['uid']).to eq('alice@example.com')
    expect(response.parsed_body.dig('data', 'email')).to eq('alice@example.com')
    user = User.from_email('alice@example.com')
    expect(user.tokens).to have_key(response.headers['client'])
  end

  it 'issues a token that authenticates later API calls' do
    post '/proxy_auth/session', headers: header
    auth = response.headers.slice('access-token', 'client', 'uid', 'token-type')
    get '/api/v1/profile', headers: auth.merge(header)
    expect(response).to have_http_status(:success)
  end

  it 'creates a UserSession row for the issued client' do
    post '/proxy_auth/session', headers: header
    user = User.from_email('alice@example.com')
    expect(user.user_sessions.pluck(:client_id)).to eq([response.headers['client']])
  end

  it 'logs a warning and still logs in when session tracking fails' do
    allow(Rails.logger).to receive(:warn)
    allow_any_instance_of(UserSessionTrackingService).to receive(:create_or_update!).and_raise(StandardError, 'boom') # rubocop:disable RSpec/AnyInstance

    post '/proxy_auth/session', headers: header

    expect(response).to have_http_status(:success)
    expect(Rails.logger).to have_received(:warn).with(/Session tracking failed: boom/)
  end

  it 'returns 403 sso_user_inactive and no headers when active_for_authentication? is false' do
    create(:user, email: 'alice@example.com', account: account)
    allow_any_instance_of(User).to receive(:active_for_authentication?).and_return(false) # rubocop:disable RSpec/AnyInstance
    post '/proxy_auth/session', headers: header
    expect_error(403, 'sso_user_inactive')
  end

  it 'returns 403 sso_account_unavailable for a suspended SSO account' do
    account.suspended!
    post '/proxy_auth/session', headers: header
    expect_error(403, 'sso_account_unavailable')
    expect(User.from_email('alice@example.com')).to be_nil
  end

  it 'returns 402 sso_agent_limit_reached at the limit' do
    allow(Account).to receive(:find_by).and_return(account)
    allow(account).to receive(:usage_limits).and_return({ agents: 0, inboxes: 0 })
    post '/proxy_auth/session', headers: header
    expect_error(402, 'sso_agent_limit_reached')
  end

  it 'ignores email, password and sso_auth_token body params' do
    victim = create(:user, email: 'victim@example.com', password: 'Test123!', account: account)
    post '/proxy_auth/session', params: { email: victim.email, password: 'Test123!', sso_auth_token: 'x' }, headers: header

    expect(response.headers['uid']).to eq('alice@example.com')
    expect(victim.reload.tokens).to be_empty
  end

  it 'ignores the identity in query and cookies' do
    post '/proxy_auth/session?email=victim@example.com', headers: { 'Cookie' => 'X-Auth-Request-Email=victim@example.com' }
    expect_error(401, 'sso_identity_missing')
  end

  it 'never changes the role of an existing administrator and gives new users agent' do
    admin = create(:user, email: 'alice@example.com', account: account, role: :administrator)
    post '/proxy_auth/session', headers: header
    expect(AccountUser.find_by(user: admin, account: account).role).to eq('administrator')

    post '/proxy_auth/session', headers: { 'X-Auth-Request-Email' => 'newbie@example.com' }
    expect(AccountUser.find_by(user: User.from_email('newbie@example.com'), account: account).role).to eq('agent')
  end

  it 'gets 401 sso_identity_changed for stale DTA headers of another user (reconciler runs first)' do
    other = create(:user, email: 'bob@example.com', account: account)
    post '/proxy_auth/session', headers: other.create_new_auth_token.merge(header)
    expect(response).to have_http_status(:unauthorized)
    expect(response.parsed_body['error_code']).to eq('sso_identity_changed')
  end

  context 'with SSO mode unset' do
    around { |example| with_modified_env('AUTH_TYPE' => nil) { example.run } }

    it 'returns 404 and creates nothing' do
      post '/proxy_auth/session', headers: header
      expect(response).to have_http_status(:not_found)
      expect(User.from_email('alice@example.com')).to be_nil
    end

    it 'leaves /auth/sign_in behaving as before' do
      post '/auth/sign_in', params: { email: 'nobody@example.com', password: 'wrong' }
      expect(response).to have_http_status(:unauthorized)
      expect(response.body).not_to include('sso_')
    end
  end
end
