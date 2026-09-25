require 'rails_helper'

RSpec.describe ProxyAuth::Provisioner do
  let(:account) { create(:account) }
  let(:sso_env) { { 'AUTH_TYPE' => 'SSO', 'SSO_ACCOUNT_ID' => account.id.to_s, 'SMB_NAME' => 'chat' } }

  around { |example| with_modified_env(sso_env) { example.run } }

  def limit_agents_to(count)
    allow(Account).to receive(:find_by).and_return(account)
    allow(account).to receive(:usage_limits).and_return({ agents: count, inboxes: count })
  end

  def provision(email = 'alice@example.com')
    described_class.call(email)
  end

  describe 'a first-seen email' do
    it 'creates a confirmed user with a random password, name from the local part and an agent membership' do
      user = provision('alice.smith@example.com')

      expect(user).to be_persisted
      expect(user.email).to eq('alice.smith@example.com')
      expect(user.name).to eq('alice.smith')
      expect(user).to be_confirmed
      expect(user.encrypted_password).to be_present
      membership = AccountUser.find_by(account_id: account.id, user_id: user.id)
      expect(membership.role).to eq('agent')
      expect(user.notification_settings.where(account_id: account.id).count).to eq(1)
    end

    it 'sets a random password nobody knows' do
      expect(provision.valid_password?('password')).to be false
    end

    it 'never sets the STI type or an administrator role' do
      user = provision
      expect(user.type).to be_nil
      expect(user).not_to be_a(SuperAdmin)
      expect(AccountUser.where(user_id: user.id).pluck(:role)).to eq(['agent'])
    end

    it 'uses a different random password per user' do
      first = provision('a@example.com')
      second = provision('b@example.com')
      expect(first.encrypted_password).not_to eq(second.encrypted_password)
    end
  end

  describe 'an existing user' do
    it 'reuses the user without creating a duplicate user or membership' do
      existing = create(:user, email: 'alice@example.com', account: account)

      expect { expect(provision).to eq(existing) }.not_to(change { [User.count, AccountUser.count] })
    end

    it 'adds an agent membership when the user has none' do
      existing = create(:user, email: 'alice@example.com')
      expect { provision }.to change { AccountUser.where(account_id: account.id, user_id: existing.id).count }.from(0).to(1)
      expect(AccountUser.find_by(account_id: account.id, user_id: existing.id).role).to eq('agent')
    end

    it 'leaves an existing administrator role unchanged' do
      admin = create(:user, email: 'alice@example.com', account: account, role: :administrator)
      provision
      expect(AccountUser.find_by(account_id: account.id, user_id: admin.id).role).to eq('administrator')
    end

    it 'confirms an existing unconfirmed user' do
      existing = create(:user, email: 'alice@example.com', account: account)
      existing.update_columns(confirmed_at: nil) # rubocop:disable Rails/SkipsModelValidations
      expect(provision).to be_confirmed
      expect(existing.reload).to be_confirmed
    end

    it 'looks up by exact match so percent and underscore never match another user' do
      victim = create(:user, email: 'victim@example.com', account: account)

      # Identity parsing rejects these before they get here; the lookup must still be literal.
      ['v%@example.com', 'v_ctim@example.com', '%@example.com', '_@example.com'].each do |email|
        expect(User.from_email(email)).to be_nil
        result = described_class.call(email)
        expect(result.id).not_to eq(victim.id)
        expect(result.email).to eq(email)
      end
      expect(User.where(email: 'victim@example.com').count).to eq(1)
    end

    it 'matches the email case-insensitively via User.from_email' do
      existing = create(:user, email: 'alice@example.com', account: account)
      expect(provision('ALICE@example.com')).to eq(existing)
    end
  end

  describe 'guard rails' do
    it 'raises AccountUnavailable and creates nothing when the SSO account is missing' do
      with_modified_env('SSO_ACCOUNT_ID' => (account.id + 1000).to_s) do
        expect { provision }.to raise_error(described_class::AccountUnavailable)
      end
      expect(User.from_email('alice@example.com')).to be_nil
    end

    it 'raises AccountUnavailable and creates nothing when the account is suspended' do
      account.suspended!
      expect { provision }.to raise_error(described_class::AccountUnavailable)
      expect(User.from_email('alice@example.com')).to be_nil
    end

    it 'raises UserInactive and creates no membership when active_for_authentication? is false' do
      existing = create(:user, email: 'alice@example.com')
      allow_any_instance_of(User).to receive(:active_for_authentication?).and_return(false) # rubocop:disable RSpec/AnyInstance
      expect { provision }.to raise_error(described_class::UserInactive)
      expect(AccountUser.where(user_id: existing.id, account_id: account.id)).to be_empty
    end

    it 'raises LimitExceeded and creates no user or membership when the agent limit is reached' do
      create(:user, account: account)
      limit_agents_to(1)

      expect { provision }.to raise_error(described_class::LimitExceeded)
      expect(User.from_email('alice@example.com')).to be_nil

      existing = create(:user, email: 'bob@example.com')
      expect { provision('bob@example.com') }.to raise_error(described_class::LimitExceeded)
      expect(AccountUser.where(user_id: existing.id, account_id: account.id)).to be_empty
    end

    it 'does not enforce the limit for an existing member' do
      existing = create(:user, email: 'alice@example.com', account: account)
      limit_agents_to(1)
      expect(provision).to eq(existing)
    end
  end

  describe 'races' do
    it 'returns the existing user when the user INSERT loses a race with RecordNotUnique' do
      winner = create(:user, email: 'alice@example.com')
      allow(User).to receive(:from_email).with('alice@example.com').and_return(nil, winner)
      allow_any_instance_of(User).to receive(:save!).and_raise(ActiveRecord::RecordNotUnique) # rubocop:disable RSpec/AnyInstance

      expect(provision).to eq(winner)
      expect(AccountUser.where(user_id: winner.id, account_id: account.id).count).to eq(1)
    end

    it 'returns the existing user when the user validation loses a race with RecordInvalid' do
      winner = create(:user, email: 'alice@example.com')
      allow(User).to receive(:from_email).with('alice@example.com').and_return(nil, winner)

      expect(provision).to eq(winner)
      expect(User.where(email: 'alice@example.com').count).to eq(1)
    end

    # The competing transaction's row is not visible to this example's own transaction, so the
    # membership check is scripted: absent before and inside the lock, present after the failed INSERT.
    [ActiveRecord::RecordNotUnique.new('uniq_user_id_per_account_id'), ActiveRecord::RecordInvalid.new(AccountUser.new)].each do |error|
      it "returns success when the membership INSERT loses a race with #{error.class.name.demodulize}" do
        user = create(:user, email: 'alice@example.com')
        allow_any_instance_of(described_class).to receive(:member?).and_return(false, false, true) # rubocop:disable RSpec/AnyInstance
        allow(AccountUser).to receive(:create!).and_raise(error)

        expect(provision).to eq(user)
        expect(AccountUser).to have_received(:create!).once
      end
    end

    it 're-raises RecordInvalid unrelated to a race' do
      allow_any_instance_of(User).to receive(:save!).and_raise(ActiveRecord::RecordInvalid.new(User.new)) # rubocop:disable RSpec/AnyInstance
      expect { provision }.to raise_error(ActiveRecord::RecordInvalid)
      expect(AccountUser.where(account_id: account.id)).to be_empty
    end

    it 're-raises RecordNotUnique when no user exists afterwards' do
      allow_any_instance_of(User).to receive(:save!).and_raise(ActiveRecord::RecordNotUnique) # rubocop:disable RSpec/AnyInstance
      expect { provision }.to raise_error(ActiveRecord::RecordNotUnique)
    end

    it 're-raises an unrelated membership error' do
      user = create(:user, email: 'alice@example.com')
      allow(AccountUser).to receive(:create!).and_raise(ActiveRecord::RecordInvalid.new(AccountUser.new))

      expect { provision }.to raise_error(ActiveRecord::RecordInvalid)
      expect(AccountUser.where(user_id: user.id, account_id: account.id)).to be_empty
    end
  end

  describe 'with SSO mode unset' do
    it 'is not referenced by any non-SSO code path' do
      callers = Dir.glob(Rails.root.join('{app,lib,config,enterprise}/**/*.rb')).select do |file|
        !file.end_with?('lib/proxy_auth/provisioner.rb') && File.read(file).include?('ProxyAuth::Provisioner')
      end
      allowed = %w[app/controllers/proxy_auth/sessions_controller.rb]
      expect(callers.map { |f| Pathname.new(f).relative_path_from(Rails.root).to_s } - allowed).to eq([])
    end
  end
end
