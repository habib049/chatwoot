require 'rails_helper'

RSpec.describe 'ProxyAuth::Provisioner concurrency' do # rubocop:disable RSpec/DescribeClass
  self.use_transactional_tests = false

  let(:email) { 'racer@example.com' }
  let!(:account) { create(:account) }

  around do |example|
    with_modified_env('AUTH_TYPE' => 'SSO', 'SSO_ACCOUNT_ID' => account.id.to_s, 'SMB_NAME' => 'chat') { example.run }
  end

  after do
    user = User.from_email(email)
    if user
      NotificationSetting.where(user_id: user.id).delete_all
      AccountUser.where(user_id: user.id).delete_all
      AccessToken.where(owner_type: 'User', owner_id: user.id).delete_all
      user.delete
    end
    NotificationSetting.where(account_id: account.id).delete_all
    AccountUser.where(account_id: account.id).delete_all
    account.delete
  end

  it 'produces one user, one membership and one notification setting for two threads provisioning the same new email' do
    start = Queue.new
    results = Array.new(2)
    errors = []

    threads = Array.new(2) do |i|
      Thread.new do
        ActiveRecord::Base.connection_pool.with_connection do
          start.pop
          results[i] = ProxyAuth::Provisioner.call(email)
        rescue StandardError => e
          errors << e
        end
      end
    end
    2.times { start << :go }
    threads.each(&:join)

    expect(errors).to eq([])
    expect(results.map(&:id).uniq.size).to eq(1)
    expect(User.where(email: email).count).to eq(1)
    expect(AccountUser.where(account_id: account.id).count).to eq(1)
    expect(NotificationSetting.where(account_id: account.id).count).to eq(1)
  end
end
