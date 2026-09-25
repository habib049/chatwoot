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
