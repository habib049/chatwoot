require 'rails_helper'

RSpec.describe 'Profile API', type: :request do
  let(:account) { create(:account) }

  describe 'GET /api/v1/profile' do
    context 'when it is an unauthenticated user' do
      it 'returns unauthorized' do
        get '/api/v1/profile'

        expect(response).to have_http_status(:unauthorized)
      end
    end

    context 'when it is an authenticated user' do
      let(:agent) { create(:user, account: account, custom_attributes: { test: 'test' }, role: :agent) }

      it 'returns current user information' do
        get '/api/v1/profile',
            headers: agent.create_new_auth_token,
            as: :json

        expect(response).to have_http_status(:success)
        expect(response).to conform_schema(200)
        json_response = response.parsed_body
        expect(json_response['id']).to eq(agent.id)
        expect(json_response['email']).to eq(agent.email)
        expect(json_response['access_token']).to eq(agent.access_token.token)
        expect(json_response['custom_attributes']['test']).to eq('test')
        expect(json_response['message_signature']).to be_nil
      end

      it 'returns an empty access token when all accounts have API and webhook access disabled' do
        account.disable_features!('api_and_webhooks')
        allow(account).to receive(:api_and_webhooks_enabled?).and_return(false)
        allow_any_instance_of(User).to receive(:accounts).and_return([account]) # rubocop:disable RSpec/AnyInstance

        get '/api/v1/profile',
            headers: agent.create_new_auth_token,
            as: :json

        json_response = response.parsed_body
        expect(json_response['access_token']).to eq('')
        expect(json_response['accounts'].first['api_and_webhooks']).to be false
      end

      it 'returns the access token when any account has API and webhook access enabled' do
        account.disable_features!('api_and_webhooks')
        enabled_account = create(:account)
        enabled_account.enable_features!('api_and_webhooks')
        create(:account_user, account: enabled_account, user: agent)
        allow(account).to receive(:api_and_webhooks_enabled?).and_return(false)
        allow(enabled_account).to receive(:api_and_webhooks_enabled?).and_return(true)
        allow_any_instance_of(User).to receive(:accounts).and_return([account, enabled_account]) # rubocop:disable RSpec/AnyInstance

        get '/api/v1/profile',
            headers: agent.create_new_auth_token,
            as: :json

        json_response = response.parsed_body
        expect(json_response['access_token']).to eq(agent.access_token.token)
        expect(json_response['accounts'].find { |item| item['id'] == enabled_account.id }['api_and_webhooks']).to be true
      end

      it 'returns the access token for self-hosted accounts even when the stored feature flag is disabled' do
        allow(ChatwootApp).to receive(:chatwoot_cloud?).and_return(false)
        account.disable_features!('api_and_webhooks')

        get '/api/v1/profile',
            headers: agent.create_new_auth_token,
            as: :json

        expect(response.parsed_body['access_token']).to eq(agent.access_token.token)
      end
    end
  end

  describe 'PUT /api/v1/profile' do
    context 'when it is an unauthenticated user' do
      it 'returns unauthorized' do
        put '/api/v1/profile'

        expect(response).to have_http_status(:unauthorized)
      end
    end

    context 'when it is an authenticated user' do
      let(:agent) { create(:user, password: 'Test123!', account: account, role: :agent) }

      it 'updates the name' do
        put '/api/v1/profile',
            params: { profile: { name: 'test' } },
            headers: agent.create_new_auth_token,
            as: :json

        expect(response).to have_http_status(:success)
        expect(response).to conform_schema(200)
        json_response = response.parsed_body
        agent.reload
        expect(json_response['id']).to eq(agent.id)
        expect(json_response['name']).to eq(agent.name)
        expect(agent.name).to eq('test')
      end

      it 'updates custom attributes' do
        put '/api/v1/profile',
            params: { profile: { phone_number: '+123456789' } },
            headers: agent.create_new_auth_token,
            as: :json

        expect(response).to have_http_status(:success)
        expect(response).to conform_schema(200)
        agent.reload

        expect(agent.custom_attributes['phone_number']).to eq('+123456789')
      end

      it 'updates the message_signature' do
        put '/api/v1/profile',
            params: { profile: { name: 'test', message_signature: 'Thanks\nMy Signature' } },
            headers: agent.create_new_auth_token,
            as: :json

        expect(response).to have_http_status(:success)
        json_response = response.parsed_body
        agent.reload
        expect(json_response['id']).to eq(agent.id)
        expect(json_response['name']).to eq(agent.name)
        expect(agent.name).to eq('test')
        expect(json_response['message_signature']).to eq('Thanks\nMy Signature')
      end

      it 'updates the password when current password is provided' do
        put '/api/v1/profile',
            params: { profile: { current_password: 'Test123!', password: 'Test1234!', password_confirmation: 'Test1234!' } },
            headers: agent.create_new_auth_token,
            as: :json

        expect(response).to have_http_status(:success)
        expect(response).to conform_schema(200)
        expect(agent.reload.valid_password?('Test1234!')).to be true
      end

      it 'does not reset the display name if updates the password' do
        display_name = agent.display_name

        put '/api/v1/profile',
            params: { profile: { current_password: 'Test123!', password: 'Test1234!', password_confirmation: 'Test1234!' } },
            headers: agent.create_new_auth_token,
            as: :json

        expect(response).to have_http_status(:success)
        expect(agent.reload.display_name).to eq(display_name)
      end

      it 'throws error when current password provided is invalid' do
        put '/api/v1/profile',
            params: { profile: { current_password: 'Test', password: 'test123', password_confirmation: 'test123' } },
            headers: agent.create_new_auth_token,
            as: :json

        expect(response).to have_http_status(:unprocessable_entity)
      end

      it 'validate name' do
        user_name = 'test' * 999
        put '/api/v1/profile',
            params: { profile: { name: user_name } },
            headers: agent.create_new_auth_token,
            as: :json

        expect(response).to have_http_status(:unprocessable_entity)
        json_response = response.parsed_body
        expect(json_response['message']).to eq('Name is too long (maximum is 255 characters)')
      end

      it 'updates avatar' do
        # no avatar before upload
        expect(agent.avatar.attached?).to be(false)
        file = fixture_file_upload(Rails.root.join('spec/assets/avatar.png'), 'image/png')
        put '/api/v1/profile',
            params: { profile: { avatar: file } },
            headers: agent.create_new_auth_token

        expect(response).to have_http_status(:success)
        agent.reload
        expect(agent.avatar.attached?).to be(true)
      end

      it 'updates the ui settings' do
        put '/api/v1/profile',
            params: { profile: { ui_settings: { is_contact_sidebar_open: false } } },
            headers: agent.create_new_auth_token,
            as: :json

        expect(response).to have_http_status(:success)
        json_response = response.parsed_body
        expect(json_response['ui_settings']['is_contact_sidebar_open']).to be(false)
      end
    end

    context 'when an authenticated user updates email' do
      let(:agent) { create(:user, password: 'Test123!', account: account, role: :agent) }

      it 'populates the unconfirmed email' do
        new_email = Faker::Internet.email
        put '/api/v1/profile',
            params: { profile: { email: new_email } },
            headers: agent.create_new_auth_token,
            as: :json

        expect(response).to have_http_status(:success)
        agent.reload

        expect(agent.unconfirmed_email).to eq(new_email)
      end
    end
  end

  describe 'DELETE /api/v1/profile/avatar' do
    let(:agent) { create(:user, password: 'Test123!', account: account, role: :agent) }

    context 'when it is an unauthenticated user' do
      it 'returns unauthorized' do
        delete '/api/v1/profile/avatar'

        expect(response).to have_http_status(:unauthorized)
      end
    end

    context 'when it is an authenticated user' do
      before do
        agent.avatar.attach(io: Rails.root.join('spec/assets/avatar.png').open, filename: 'avatar.png', content_type: 'image/png')
      end

      it 'deletes the agent avatar' do
        delete '/api/v1/profile/avatar',
               headers: agent.create_new_auth_token,
               as: :json

        expect(response).to have_http_status(:success)
        json_response = response.parsed_body
        expect(json_response['avatar_url']).to be_empty
      end
    end
  end

  describe 'POST /api/v1/profile/availability' do
    context 'when it is an unauthenticated user' do
      it 'returns unauthorized' do
        post '/api/v1/profile/availability'

        expect(response).to have_http_status(:unauthorized)
      end
    end

    context 'when it is an authenticated user' do
      let(:agent) { create(:user, password: 'Test123!', account: account, role: :agent) }

      it 'updates the availability status' do
        post '/api/v1/profile/availability',
             params: { profile: { availability: 'busy', account_id: account.id } },
             headers: agent.create_new_auth_token,
             as: :json

        expect(response).to have_http_status(:success)
        expect(OnlineStatusTracker.get_status(account.id, agent.id)).to eq('busy')
      end
    end
  end

  describe 'POST /api/v1/profile/auto_offline' do
    context 'when it is an unauthenticated user' do
      it 'returns unauthorized' do
        post '/api/v1/profile/auto_offline'
        expect(response).to have_http_status(:unauthorized)
      end
    end

    context 'when it is an authenticated user' do
      let(:agent) { create(:user, password: 'Test123!', account: account, role: :agent) }

      it 'updates the auto offline status' do
        post '/api/v1/profile/auto_offline',
             params: { profile: { auto_offline: false, account_id: account.id } },
             headers: agent.create_new_auth_token,
             as: :json

        expect(response).to have_http_status(:success)
        json_response = response.parsed_body
        expect(json_response['accounts'].first['auto_offline']).to be(false)
      end
    end
  end

  describe 'PUT /api/v1/profile/set_active_account' do
    context 'when it is an unauthenticated user' do
      it 'returns unauthorized' do
        put '/api/v1/profile/set_active_account'

        expect(response).to have_http_status(:unauthorized)
      end
    end

    context 'when it is an authenticated user' do
      let(:agent) { create(:user, password: 'Test123!', account: account, role: :agent) }

      it 'updates the last active account id' do
        put '/api/v1/profile/set_active_account',
            params: { profile: { account_id: account.id } },
            headers: agent.create_new_auth_token,
            as: :json

        expect(response).to have_http_status(:success)
      end
    end
  end

  describe 'POST /api/v1/profile/resend_confirmation' do
    context 'when it is an unauthenticated user' do
      it 'returns unauthorized' do
        post '/api/v1/profile/resend_confirmation'

        expect(response).to have_http_status(:unauthorized)
      end
    end

    context 'when it is an authenticated user' do
      let(:agent) do
        create(:user, password: 'Test123!', email: 'test-unconfirmed@email.com', account: account, role: :agent,
                      unconfirmed_email: 'test-unconfirmed@email.com')
      end

      it 'does not send the confirmation email if the user is already confirmed' do
        expect do
          post '/api/v1/profile/resend_confirmation',
               headers: agent.create_new_auth_token,
               as: :json
        end.not_to have_enqueued_mail(Devise::Mailer, :confirmation_instructions)

        expect(response).to have_http_status(:success)
      end

      it 'resends the confirmation email if the user is unconfirmed' do
        agent.confirmed_at = nil
        agent.save!

        expect do
          post '/api/v1/profile/resend_confirmation',
               headers: agent.create_new_auth_token,
               as: :json
        end.to have_enqueued_mail(Devise::Mailer, :confirmation_instructions)

        expect(response).to have_http_status(:success)
      end
    end
  end

  describe 'POST /api/v1/profile/reset_access_token' do
    context 'when it is an unauthenticated user' do
      it 'returns unauthorized' do
        post '/api/v1/profile/reset_access_token'

        expect(response).to have_http_status(:unauthorized)
      end
    end

    context 'when it is an authenticated user' do
      let(:agent) { create(:user, account: account, role: :agent) }

      it 'regenerates the access token' do
        old_token = agent.access_token.token

        post '/api/v1/profile/reset_access_token',
             headers: agent.create_new_auth_token,
             as: :json

        expect(response).to have_http_status(:success)
        agent.reload
        expect(agent.access_token.token).not_to eq(old_token)
        json_response = response.parsed_body
        expect(json_response['access_token']).to eq(agent.access_token.token)
      end

      it 'regenerates the stored token but returns an empty token when no account has API and webhook access enabled' do
        account.disable_features!('api_and_webhooks')
        allow(account).to receive(:api_and_webhooks_enabled?).and_return(false)
        allow_any_instance_of(User).to receive(:accounts).and_return([account]) # rubocop:disable RSpec/AnyInstance
        old_token = agent.access_token.token

        post '/api/v1/profile/reset_access_token',
             headers: agent.create_new_auth_token,
             as: :json

        expect(response).to have_http_status(:success)
        expect(agent.reload.access_token.token).not_to eq(old_token)
        expect(response.parsed_body['access_token']).to eq('')
      end
    end
  end

  describe 'PUT /api/v1/profile in SSO mode' do
    let(:sso_env) { { 'AUTH_TYPE' => 'SSO', 'SSO_ACCOUNT_ID' => '1', 'SMB_NAME' => 'chat' } }
    let(:agent) { create(:user, password: 'Test123!', email: 'Agent@Example.com', account: account, role: :agent) }

    def put_profile(profile)
      put '/api/v1/profile', params: { profile: profile }, headers: agent.create_new_auth_token, as: :json
    end

    around { |example| with_modified_env(sso_env) { example.run } }

    it 'rejects a password change with 403 and changes nothing' do
      digest = agent.encrypted_password
      put_profile(current_password: 'Test123!', password: 'Test1234!', password_confirmation: 'Test1234!')

      expect(response).to have_http_status(:forbidden)
      expect(response.parsed_body['error_code']).to eq('sso_local_auth_disabled')
      expect(agent.reload.encrypted_password).to eq(digest)
    end

    %w[password password_confirmation current_password].each do |key|
      it "rejects a non-blank #{key} on its own with 403" do
        put_profile(key => 'x', :name => 'Renamed')
        expect(response).to have_http_status(:forbidden)
        expect(agent.reload.name).not_to eq('Renamed')
      end
    end

    it 'rejects an email change to a different address with 403 and does not change the user' do
      put_profile(email: 'someone.else@example.com', name: 'Renamed')

      expect(response).to have_http_status(:forbidden)
      expect(response.parsed_body['error_code']).to eq('sso_local_auth_disabled')
      agent.reload
      expect(agent.email).to eq('agent@example.com')
      expect(agent.name).not_to eq('Renamed')
    end

    it 'allows name, display_name, message_signature and ui_settings updates' do
      put_profile(name: 'New Name', display_name: 'Newbie', message_signature: 'Cheers', ui_settings: { theme: 'dark' })

      expect(response).to have_http_status(:success)
      agent.reload
      expect([agent.name, agent.display_name, agent.message_signature]).to eq(['New Name', 'Newbie', 'Cheers'])
      expect(agent.ui_settings['theme']).to eq('dark')
    end

    it 'allows an unchanged email in a different case or with whitespace, and blank password fields' do
      put_profile(email: '  AGENT@example.COM ', name: 'Same Email', password: '', password_confirmation: '', current_password: '')

      expect(response).to have_http_status(:success)
      expect(agent.reload.name).to eq('Same Email')
    end

    it 'allows an avatar update' do
      put '/api/v1/profile',
          params: { profile: { avatar: fixture_file_upload(Rails.root.join('spec/assets/avatar.png'), 'image/png') } },
          headers: agent.create_new_auth_token
      expect(response).to have_http_status(:success)
      expect(agent.reload.avatar).to be_attached
    end

    credential_keys = %w[email password password_confirmation current_password]
    [['array', ['a']], ['hash', { 'a' => 'b' }], ['number', 5], ['null', nil], ['boolean', true]].each do |label, value|
      credential_keys.each do |key|
        it "returns 422 sso_invalid_param for a #{label} #{key}" do
          digest = agent.encrypted_password
          put_profile(key => value, :name => 'Renamed')

          expect(response).to have_http_status(422)
          expect(response.parsed_body['error_code']).to eq('sso_invalid_param')
          agent.reload
          expect(agent.encrypted_password).to eq(digest)
          expect(agent.name).not_to eq('Renamed')
        end
      end
    end

    it 'returns 422 when profile itself is not a hash' do
      put_profile('just-a-string')
      expect(response).to have_http_status(422)
      expect(response.parsed_body['error_code']).to eq('sso_invalid_param')
    end

    it 'ignores the DB-backed DISABLE_USER_PROFILE_UPDATE flag' do
      InstallationConfig.where(name: 'DISABLE_USER_PROFILE_UPDATE').delete_all
      InstallationConfig.create!(name: 'DISABLE_USER_PROFILE_UPDATE', serialized_value: { value: false }.with_indifferent_access)
      GlobalConfig.clear_cache
      put_profile(email: 'other@example.com')
      expect(response).to have_http_status(:forbidden)
    ensure
      GlobalConfig.clear_cache
    end

    it 'does not treat a differently-cased param name as the password param' do
      digest = agent.encrypted_password
      put_profile(Password: 'Test1234!', name: 'Renamed')
      expect(response).to have_http_status(:success)
      expect(agent.reload.encrypted_password).to eq(digest)
    end

    it 'still returns 401 for an unauthenticated request' do
      put '/api/v1/profile', params: { profile: { password: 'x' } }, as: :json
      expect(response).to have_http_status(:unauthorized)
    end
  end

  describe 'PUT /api/v1/profile with SSO mode unset' do
    let(:agent) { create(:user, password: 'Test123!', account: account, role: :agent) }

    around { |example| with_modified_env('AUTH_TYPE' => nil) { example.run } }

    it 'still changes the password and the email as before' do
      put '/api/v1/profile',
          params: { profile: { current_password: 'Test123!', password: 'Test1234!', password_confirmation: 'Test1234!' } },
          headers: agent.create_new_auth_token, as: :json
      expect(response).to have_http_status(:success)
      expect(agent.reload.valid_password?('Test1234!')).to be true

      put '/api/v1/profile', params: { profile: { email: 'renamed@example.com' } }, headers: agent.create_new_auth_token, as: :json
      expect(response).to have_http_status(:success)
      expect(response.body).not_to include('sso_')
    end

    it 'does not return 422 sso_invalid_param for odd types' do
      put '/api/v1/profile', params: { profile: { email: ['a'] } }, headers: agent.create_new_auth_token, as: :json
      expect(response.body).not_to include('sso_invalid_param')
    end
  end
end
