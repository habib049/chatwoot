require 'rails_helper'

RSpec.describe SsoMode do
  let(:sso_env) { { 'AUTH_TYPE' => 'SSO', 'SSO_ACCOUNT_ID' => '1', 'SMB_NAME' => 'chat' } }

  def sso(extra = {}, &)
    with_modified_env(sso_env.merge(extra), &)
  end

  describe '.enabled?' do
    it 'is true only for exactly SSO' do
      with_modified_env('AUTH_TYPE' => 'SSO') { expect(described_class.enabled?).to be true }
    end

    it 'pins that surrounding whitespace is stripped and so turns the mode on' do
      with_modified_env('AUTH_TYPE' => ' SSO ') { expect(described_class.enabled?).to be true }
    end

    ['', 'Sso', 'sso', 'OIDC', 'true', 'SSO2'].each do |value|
      it "is false for AUTH_TYPE=#{value.inspect}" do
        with_modified_env('AUTH_TYPE' => value) { expect(described_class.enabled?).to be false }
      end
    end

    it 'is false when AUTH_TYPE is unset' do
      with_modified_env('AUTH_TYPE' => nil) { expect(described_class.enabled?).to be false }
    end

    it 'stays false when an installation config or GlobalConfig says SSO but ENV does not' do
      InstallationConfig.create!(name: 'AUTH_TYPE', serialized_value: { value: 'SSO' }.with_indifferent_access)
      GlobalConfig.clear_cache
      with_modified_env('AUTH_TYPE' => nil) do
        expect(GlobalConfig.get_value('AUTH_TYPE')).to eq('SSO')
        expect(described_class.enabled?).to be false
      end
    ensure
      GlobalConfig.clear_cache
    end
  end

  describe '.validate!' do
    %w[Sso sso sSO].each do |value|
      it "raises for AUTH_TYPE=#{value} regardless of mode" do
        with_modified_env('AUTH_TYPE' => value) { expect { described_class.validate! }.to raise_error(SsoMode::InvalidConfig, /AUTH_TYPE/) }
      end
    end

    it 'raises for a case-only difference even with surrounding whitespace' do
      with_modified_env('AUTH_TYPE' => ' sso ') { expect { described_class.validate! }.to raise_error(SsoMode::InvalidConfig) }
    end

    it 'ignores malformed SSO_* values when mode is off' do
      with_modified_env('AUTH_TYPE' => nil, 'SSO_ACCOUNT_ID' => 'abc', 'SMB_NAME' => 'BAD.NAME',
                        'SESSION_COOKIE_MAX_AGE_SECONDS' => '8h', 'DEFAULT_EMAIL_DOMAIN' => 'x', 'SSO_TRUSTED_PROXY_CIDRS' => 'nope') do
        expect { described_class.validate! }.not_to raise_error
      end
    end

    it 'passes with a valid SSO configuration' do
      sso { expect { described_class.validate! }.not_to raise_error }
    end

    it 'raises in SSO mode when a required or malformed value is present' do
      sso('SMB_NAME' => nil) { expect { described_class.validate! }.to raise_error(SsoMode::InvalidConfig, /SMB_NAME/) }
      sso('SSO_ACCOUNT_ID' => nil) { expect { described_class.validate! }.to raise_error(SsoMode::InvalidConfig, /SSO_ACCOUNT_ID/) }
      sso('SESSION_COOKIE_MAX_AGE_SECONDS' => '8h') { expect { described_class.validate! }.to raise_error(SsoMode::InvalidConfig) }
      sso('DEFAULT_EMAIL_DOMAIN' => 'Bad') { expect { described_class.validate! }.to raise_error(SsoMode::InvalidConfig) }
      sso('SSO_TRUSTED_PROXY_CIDRS' => 'nope') { expect { described_class.validate! }.to raise_error(SsoMode::InvalidConfig) }
    end
  end

  describe '.session_lifetime_seconds' do
    it 'defaults to 604800' do
      sso('SESSION_COOKIE_MAX_AGE_SECONDS' => nil) { expect(described_class.session_lifetime_seconds).to eq(604_800) }
    end

    it 'accepts the bounds and an in-range value' do
      %w[60 3600 31536000].each do |v|
        sso('SESSION_COOKIE_MAX_AGE_SECONDS' => v) { expect(described_class.session_lifetime_seconds).to eq(v.to_i) }
      end
    end

    ['8h', '0', 'abc', '', '-1', '1.5', ' 604800', '604800 ', "604800\n", '59', '31536001', '0000000060x'].each do |value|
      it "rejects #{value.inspect} naming the variable" do
        sso('SESSION_COOKIE_MAX_AGE_SECONDS' => value) do
          expect { described_class.session_lifetime_seconds }.to raise_error(SsoMode::InvalidConfig, /SESSION_COOKIE_MAX_AGE_SECONDS/)
        end
      end
    end
  end

  describe '.token_lifespan' do
    it 'is session_lifetime_seconds.seconds in SSO mode' do
      sso('SESSION_COOKIE_MAX_AGE_SECONDS' => '3600') { expect(described_class.token_lifespan).to eq(3600.seconds) }
    end

    it 'is 2.months when mode is off' do
      with_modified_env('AUTH_TYPE' => nil, 'SESSION_COOKIE_MAX_AGE_SECONDS' => '3600') { expect(described_class.token_lifespan).to eq(2.months) }
    end
  end

  describe '.account_id' do
    it 'returns the integer id' do
      sso('SSO_ACCOUNT_ID' => '4242') { expect(described_class.account_id).to eq(4242) }
    end

    [nil, '0', '01', 'abc', '1.5', '12345678901', '', ' 1', '-1'].each do |value|
      it "rejects #{value.inspect}" do
        sso('SSO_ACCOUNT_ID' => value) { expect { described_class.account_id }.to raise_error(SsoMode::InvalidConfig, /SSO_ACCOUNT_ID/) }
      end
    end
  end

  describe '.portal_name' do
    it 'returns a valid value unchanged' do
      sso('SMB_NAME' => 'my-portal1') { expect(described_class.portal_name).to eq('my-portal1') }
    end

    [nil, '', 'Chat', 'a.b', '-abc', 'abc-', 'a b', 'a_b', "chat\n"].each do |value|
      it "rejects #{value.inspect}" do
        sso('SMB_NAME' => value) { expect { described_class.portal_name }.to raise_error(SsoMode::InvalidConfig, /SMB_NAME/) }
      end
    end
  end

  describe '.default_email_domain' do
    it 'returns nil when unset' do
      sso('DEFAULT_EMAIL_DOMAIN' => nil) { expect(described_class.default_email_domain).to be_nil }
    end

    it 'returns a valid domain' do
      sso('DEFAULT_EMAIL_DOMAIN' => 'mail.example.com') { expect(described_class.default_email_domain).to eq('mail.example.com') }
    end

    ['', 'localhost', 'Example.com', 'example..com', '.example.com', 'example.com.', 'ex ample.com', 'exa_mple.com'].each do |value|
      it "rejects #{value.inspect}" do
        sso('DEFAULT_EMAIL_DOMAIN' => value) { expect { described_class.default_email_domain }.to raise_error(SsoMode::InvalidConfig) }
      end
    end
  end

  describe '.trusted_proxy_ranges' do
    it 'returns an empty list when unset' do
      sso('SSO_TRUSTED_PROXY_CIDRS' => nil) { expect(described_class.trusted_proxy_ranges).to eq([]) }
    end

    it 'parses a comma separated list' do
      sso('SSO_TRUSTED_PROXY_CIDRS' => '10.0.0.0/8,::1') do
        ranges = described_class.trusted_proxy_ranges
        expect(ranges.size).to eq(2)
        expect(ranges.first.include?(IPAddr.new('10.1.2.3'))).to be true
      end
    end

    ['nope', '10.0.0.0/33', '10.0.0.0/8,', '10.0.0.0/8,,::1', '', 'example.com', ' 10.0.0.0/8'].each do |value|
      it "rejects #{value.inspect}" do
        sso('SSO_TRUSTED_PROXY_CIDRS' => value) do
          expect { described_class.trusted_proxy_ranges }.to raise_error(SsoMode::InvalidConfig, /SSO_TRUSTED_PROXY_CIDRS/)
        end
      end
    end
  end
end
