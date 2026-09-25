require 'rails_helper'

RSpec.describe 'SSO local credential guard with enterprise SAML', type: :request do
  let(:sso_env) { { 'AUTH_TYPE' => 'SSO', 'SSO_ACCOUNT_ID' => '1', 'SMB_NAME' => 'chat', 'FRONTEND_URL' => 'http://www.example.com' } }
  let!(:account) { create(:account) }

  before do
    allow(ChatwootApp).to receive(:enterprise?).and_return(true)
    allow(GlobalConfigService).to receive(:load).and_call_original
    allow(GlobalConfigService).to receive(:load).with('FRONTEND_URL', 'http://localhost:3000').and_return('http://www.example.com')
    account.enable_features!('saml')
    create(:account_saml_settings, account: account)
    OmniAuth.config.test_mode = true
    OmniAuth.config.mock_auth[:saml] = OmniAuth::AuthHash.new(provider: 'saml', uid: '1', info: { name: 'Sam', email: 'saml-user@example.com' })
  end

  after do
    OmniAuth.config.test_mode = false
    OmniAuth.config.mock_auth[:saml] = nil
  end

  it 'still logs in via SAML when SSO mode is off (control)' do
    with_modified_env('FRONTEND_URL' => 'http://www.example.com') do
      get "/omniauth/saml/callback?account_id=#{account.id}"
      expect(response).to have_http_status(:redirect)
      expect(User.from_email('saml-user@example.com')).to be_present
    end
  end

  it 'denies SAML callback, request phase and saml_login even with AccountSamlSettings and the saml feature enabled' do
    with_modified_env(sso_env) do
      get "/omniauth/saml/callback?account_id=#{account.id}"
      expect(response).to have_http_status(:forbidden)
      expect(response.parsed_body['error_code']).to eq('sso_local_auth_disabled')

      post "/omniauth/saml/callback?account_id=#{account.id}"
      expect(response).to have_http_status(:forbidden)

      get "/auth/saml?account_id=#{account.id}"
      expect(response).to have_http_status(:forbidden)

      post '/api/v1/auth/saml_login', params: { email: 'saml-user@example.com' }
      expect(response).to have_http_status(:forbidden)

      expect(User.from_email('saml-user@example.com')).to be_nil
    end
  end
end
