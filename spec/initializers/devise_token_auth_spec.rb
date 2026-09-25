require 'rails_helper'

RSpec.describe 'devise_token_auth initializer' do # rubocop:disable RSpec/DescribeClass
  let(:sso_env) { { 'AUTH_TYPE' => 'SSO', 'SSO_ACCOUNT_ID' => '1', 'SMB_NAME' => 'chat' } }
  let(:initializer) { Rails.root.join('config/initializers/devise_token_auth.rb') }

  around do |example|
    original = DeviseTokenAuth.token_lifespan
    example.run
  ensure
    DeviseTokenAuth.token_lifespan = original
  end

  def lifespan_after_loading(env)
    with_modified_env(env) do
      load initializer
      DeviseTokenAuth.token_lifespan
    end
  end

  it 'equals SESSION_COOKIE_MAX_AGE_SECONDS in SSO mode' do
    expect(lifespan_after_loading(sso_env.merge('SESSION_COOKIE_MAX_AGE_SECONDS' => '3600'))).to eq(3600.seconds)
  end

  it 'defaults to 604800 seconds in SSO mode when the env is unset' do
    expect(lifespan_after_loading(sso_env.merge('SESSION_COOKIE_MAX_AGE_SECONDS' => nil))).to eq(604_800.seconds)
  end

  it 'is 2 months when SSO mode is off' do
    expect(lifespan_after_loading('AUTH_TYPE' => nil, 'SESSION_COOKIE_MAX_AGE_SECONDS' => '3600')).to eq(2.months)
  end

  it 'does not slide the expiry: headers do not change on each request' do
    expect(DeviseTokenAuth.change_headers_on_each_request).to be false
  end

  %w[8h 0 abc -1 1.5 59 31536001].each do |bad|
    it "raises SsoMode::InvalidConfig instead of using #{bad}" do
      with_modified_env(sso_env.merge('SESSION_COOKIE_MAX_AGE_SECONDS' => bad)) do
        expect { SsoMode.validate! }.to raise_error(SsoMode::InvalidConfig)
        expect { load initializer }.to raise_error(SsoMode::InvalidConfig)
      end
    end
  end

  it 'leaves the configured lifespan restored after the examples' do
    expect(DeviseTokenAuth.token_lifespan).to eq(2.months)
  end
end
