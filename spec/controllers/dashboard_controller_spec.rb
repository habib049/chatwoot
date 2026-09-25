require 'rails_helper'

describe '/app/login', type: :request do
  context 'without DEFAULT_LOCALE' do
    it 'renders the dashboard' do
      get '/app/login'
      expect(response).to have_http_status(:success)
    end
  end

  context 'with DEFAULT_LOCALE' do
    it 'renders the dashboard' do
      with_modified_env DEFAULT_LOCALE: 'pt_BR' do
        get '/app/login'
        expect(response).to have_http_status(:success)
        expect(response.body).to include "selectedLocale: 'pt_BR'"
      end
    end
  end

  context 'with SSO config' do
    it 'renders ssoMode true and smbName when AUTH_TYPE is SSO' do
      with_modified_env AUTH_TYPE: 'SSO', SSO_ACCOUNT_ID: '1', SMB_NAME: 'portal' do
        get '/app/login'
        expect(response.body).to include 'ssoMode: true,'
        expect(response.body).to include "smbName: 'portal',"
      end
    end

    it 'renders ssoMode false and an empty smbName when AUTH_TYPE is unset' do
      with_modified_env AUTH_TYPE: nil, SMB_NAME: 'portal' do
        get '/app/login'
        expect(response.body).to include 'ssoMode: false,'
        expect(response.body).to include "smbName: '',"
        expect(response.body).not_to include 'portal'
      end
    end
  end

  context 'with the installation onboarding flag' do
    before { Redis::Alfred.set(Redis::Alfred::CHATWOOT_INSTALLATION_ONBOARDING, true) }

    after { Redis::Alfred.delete(Redis::Alfred::CHATWOOT_INSTALLATION_ONBOARDING) }

    it 'redirects to /installation/onboarding when SSO mode is off (unchanged)' do
      with_modified_env AUTH_TYPE: nil do
        get '/app/login'
        expect(response).to redirect_to('/installation/onboarding')
      end
    end

    it 'does not redirect to /installation/onboarding in SSO mode even when the Redis flag is set' do
      with_modified_env AUTH_TYPE: 'SSO', SSO_ACCOUNT_ID: '1', SMB_NAME: 'portal' do
        get '/app/login'
        expect(response).to have_http_status(:success)
      end
    end
  end

  context 'with login methods' do
    before do
      InstallationConfig.where(name: 'ENABLE_GOOGLE_OAUTH_LOGIN').delete_all
      InstallationConfig.create!(name: 'ENABLE_GOOGLE_OAUTH_LOGIN', serialized_value: { value: true }.with_indifferent_access)
      GlobalConfig.clear_cache
    end

    after { GlobalConfig.clear_cache }

    it 'renders an empty allowedLoginMethods in SSO mode even when ENABLE_GOOGLE_OAUTH_LOGIN is true in the DB' do
      with_modified_env AUTH_TYPE: 'SSO', SSO_ACCOUNT_ID: '1', SMB_NAME: 'portal' do
        get '/app/login'
        expect(response.body).to include 'allowedLoginMethods: [],'
      end
    end

    it 'keeps the email and google_oauth login methods when SSO mode is off (unchanged)' do
      with_modified_env AUTH_TYPE: nil do
        get '/app/login'
        expect(response.body).to include 'allowedLoginMethods: ["email","google_oauth"'
      end
    end
  end

  context 'with the page-level identity reconciliation' do
    let(:sso_env) { { AUTH_TYPE: 'SSO', SSO_ACCOUNT_ID: '1', SMB_NAME: 'portal', SSO_TRUSTED_PROXY_CIDRS: nil } }
    let(:session_cookie) { { 'uid' => 'alice@example.com', 'client' => 'c', 'access-token' => 't' }.to_json }

    def load_page(cookie: :none, proxy_email: :none)
      headers = {}
      headers['Cookie'] = "cw_d_session_info=#{CGI.escape(cookie)}" unless cookie == :none
      headers['X-Auth-Request-Email'] = proxy_email unless proxy_email == :none
      get '/app/login', headers: headers
    end

    def session_cookie_lines
      Array(response.headers['Set-Cookie']).select { |line| line.start_with?('cw_d_session_info=') }
    end

    def expired?
      session_cookie_lines.any? { |line| line.include?('expires=Thu, 01 Jan 1970') }
    end

    around { |example| with_modified_env(sso_env) { example.run } }

    it 'expires cw_d_session_info when uid differs from the proxy identity, and still renders the page' do
      load_page(cookie: session_cookie, proxy_email: 'bob@example.com')
      expect(response).to have_http_status(:success)
      expect(expired?).to be true
    end

    it 'keeps the cookie when uid matches, case and whitespace insensitive on both sides' do
      load_page(cookie: { 'uid' => ' Alice@Example.com ' }.to_json, proxy_email: '  ALICE@example.com ')
      expect(session_cookie_lines).to be_empty
    end

    it 'keeps a usable cookie when the header is absent or blank' do
      load_page(cookie: session_cookie)
      expect(session_cookie_lines).to be_empty
      load_page(cookie: session_cookie, proxy_email: '   ')
      expect(session_cookie_lines).to be_empty
    end

    it 'expires the cookie when the header is unusable' do
      load_page(cookie: session_cookie, proxy_email: 'a@b@c.com')
      expect(expired?).to be true
    end

    it 'expires an unparsable cookie without a 500' do
      ['not json', '{"uid":', '', '{'].reject(&:empty?).each do |bad|
        load_page(cookie: bad)
        expect(response).to have_http_status(:success)
        expect(expired?).to be true
      end
    end

    it 'expires a cookie whose uid is null, an array, a number, a hash or a boolean' do
      ['null', '[]', '["alice@example.com"]', '5', '{"uid":null}', '{"uid":["a@example.com"]}', '{"uid":5}', '{"uid":{"a":1}}', '{"uid":true}',
       '"just a string"'].each do |bad|
        load_page(cookie: bad)
        expect(response).to have_http_status(:success)
        expect(expired?).to be(true), "expected #{bad} to be expired"
      end
    end

    it 'expires a cookie nested deeper than the JSON nesting limit without raising' do
      deep = "#{'{"a":' * 8}1#{'}' * 8}"
      load_page(cookie: deep)
      expect(response).to have_http_status(:success)
      expect(expired?).to be true
    end

    it 'sends no Set-Cookie for a missing cookie' do
      load_page(proxy_email: 'bob@example.com')
      expect(session_cookie_lines).to be_empty
    end

    it 'runs before the other before-actions' do
      filters = DashboardController._process_action_callbacks.select { |c| c.kind == :before }.map(&:filter)
      own = %i[reconcile_page_identity set_application_pack set_global_config set_dashboard_scripts ensure_installation_onboarding
               render_hc_if_custom_domain ensure_html_format]
      expect(filters.select { |f| own.include?(f) }).to eq(own)
    end

    it 'leaves the cookie untouched when SSO mode is off' do
      with_modified_env(AUTH_TYPE: nil) do
        load_page(cookie: session_cookie, proxy_email: 'bob@example.com')
        expect(session_cookie_lines).to be_empty
        load_page(cookie: 'garbage')
        expect(session_cookie_lines).to be_empty
      end
    end
  end

  context 'with non-HTML format' do
    it 'returns not acceptable for JSON with error message' do
      get '/app/login', headers: { 'Accept' => 'application/json' }
      expect(response).to have_http_status(:not_acceptable)
      expect(response.parsed_body).to eq({ 'error' => 'Please use API routes instead of dashboard routes for JSON requests' })
    end
  end

  # Routes are loaded once on app start
  # hence Rails.application.reload_routes! is used in this spec
  # ref : https://stackoverflow.com/a/63584877/939299
  context 'with CW_API_ONLY_SERVER true' do
    it 'returns 404' do
      with_modified_env CW_API_ONLY_SERVER: 'true' do
        Rails.application.reload_routes!
        get '/app/login'
        expect(response).to have_http_status(:not_found)
      end
      Rails.application.reload_routes!
    end
  end
end
