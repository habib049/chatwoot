require 'rails_helper'

RSpec.describe ProxyAuth::Identity do
  let(:sso_env) do
    { 'AUTH_TYPE' => 'SSO', 'SSO_ACCOUNT_ID' => '1', 'SMB_NAME' => 'chat', 'DEFAULT_EMAIL_DOMAIN' => nil, 'SSO_TRUSTED_PROXY_CIDRS' => nil }
  end

  def parse(header = :none, remote_addr: '10.0.0.1', env: {})
    rack_env = { 'REMOTE_ADDR' => remote_addr }
    rack_env['HTTP_X_AUTH_REQUEST_EMAIL'] = header unless header == :none
    with_modified_env(sso_env.merge(env)) { described_class.from_request(ActionDispatch::TestRequest.create(rack_env)) }
  end

  it 'returns absent when the header is missing' do
    expect(parse.status).to eq(:absent)
    expect(parse.email).to be_nil
  end

  it 'returns absent when the header is whitespace only' do
    expect(parse("  \t ").status).to eq(:absent)
    expect(parse('').status).to eq(:absent)
  end

  it 'returns present with a lowercased stripped email for a valid header' do
    result = parse('  ALICE@Example.com  ')
    expect(result.status).to eq(:present)
    expect(result.email).to eq('alice@example.com')
  end

  it 'accepts plus, dot, underscore and hyphen in the local part and subdomains' do
    expect(parse('a.b_c+d-e@mail.example.co.uk').email).to eq('a.b_c+d-e@mail.example.co.uk')
  end

  describe 'bare usernames' do
    it 'synthesizes the email from DEFAULT_EMAIL_DOMAIN' do
      result = parse('Alice', env: { 'DEFAULT_EMAIL_DOMAIN' => 'example.com' })
      expect([result.status, result.email]).to eq([:present, 'alice@example.com'])
    end

    it 'returns unusable when DEFAULT_EMAIL_DOMAIN is unset' do
      expect(parse('alice').status).to eq(:unusable)
    end

    it 'applies the local part rules to a bare username' do
      expect(parse('a b', env: { 'DEFAULT_EMAIL_DOMAIN' => 'example.com' }).status).to eq(:unusable)
      expect(parse('a%', env: { 'DEFAULT_EMAIL_DOMAIN' => 'example.com' }).status).to eq(:unusable)
    end

    it 'rejects a synthesized address whose domain fails the TLD rule' do
      expect(parse('alice', env: { 'DEFAULT_EMAIL_DOMAIN' => 'example.123' }).status).to eq(:unusable)
    end
  end

  describe 'unusable input matrix' do
    {
      'multiple @' => 'a@b@example.com',
      'leading @' => '@example.com',
      'comma' => 'a,b@example.com',
      'embedded space' => 'a b@example.com',
      'control character' => "a\u0001b@example.com",
      'newline inside' => "a\nb@example.com",
      'non-ASCII' => 'alicé@example.com',
      'percent sign' => 'a%b@example.com',
      'wildcard' => 'v%@example.com',
      'wildcards everywhere' => '%@%.%',
      'underscore in domain' => 'a@exa_mple.com',
      'no dot after @' => 'a@localhost',
      'dot right after @' => 'a@.example.com',
      'single label domain' => 'a@com.',
      'trailing dot' => 'a@example.com.',
      'numeric tld' => 'a@example.123',
      'one letter tld' => 'a@example.c',
      'hyphen-leading label' => 'a@-example.com',
      'quote' => '"a"@example.com',
      'over 254 bytes' => "#{'a' * 250}@example.com",
      'local part over 64' => "#{'a' * 65}@example.com",
      'invalid encoding' => "a\xFF@example.com".dup.force_encoding('UTF-8'),
      'binary high bytes' => "a\xC3\xA9@example.com".dup.force_encoding('ASCII-8BIT')
    }.each do |name, value|
      it "returns unusable for #{name}" do
        result = parse(value)
        expect(result.status).to eq(:unusable)
        expect(result.email).to be_nil
      end
    end
  end

  it 'returns quickly for adversarial input' do
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    result = parse('!@!.' * 60)
    expect(result.status).to eq(:unusable)
    expect(Process.clock_gettime(Process::CLOCK_MONOTONIC) - started).to be < 0.5
  end

  it 'does not use a regex before the length and ASCII checks (no polynomial backtracking on long input)' do
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    ["a@#{('a.' * 50_000)}", 'a' * 1_000_000, '@' * 100_000].each { |v| expect(parse(v).status).to eq(:unusable) }
    expect(Process.clock_gettime(Process::CLOCK_MONOTONIC) - started).to be < 0.5
  end

  it 'never raises for non-String header values and treats them as absent' do
    [nil, ['a@example.com'], 42, { 'a' => 'b' }, 1.5, true].each do |value|
      expect(parse(value).status).to eq(:absent), "expected absent for #{value.inspect}"
    end
  end

  it 'never returns present for wildcard values' do
    ['v%@example.com', '%@%.%', '_@example.com%', 'a@%.com'].each { |v| expect(parse(v).status).not_to eq(:present) }
  end

  describe 'SSO_TRUSTED_PROXY_CIDRS' do
    let(:cidrs) { { 'SSO_TRUSTED_PROXY_CIDRS' => '10.0.0.0/8,::1' } }

    it 'returns present for a peer inside the ranges' do
      expect(parse('a@example.com', remote_addr: '10.2.3.4', env: cidrs).status).to eq(:present)
      expect(parse('a@example.com', remote_addr: '::1', env: cidrs).status).to eq(:present)
    end

    it 'returns absent for a peer outside the ranges, ignoring a spoofed header' do
      expect(parse('admin@example.com', remote_addr: '203.0.113.9', env: cidrs).status).to eq(:absent)
    end

    it 'counts an unparseable or missing REMOTE_ADDR as outside' do
      expect(parse('a@example.com', remote_addr: 'not-an-ip', env: cidrs).status).to eq(:absent)
      expect(parse('a@example.com', remote_addr: '', env: cidrs).status).to eq(:absent)
    end

    it 'applies no peer check when the list is unset' do
      expect(parse('a@example.com', remote_addr: '203.0.113.9').status).to eq(:present)
      expect(parse('a@example.com', remote_addr: 'not-an-ip').status).to eq(:present)
    end
  end

  # R7 (no acceptance criterion in the plan; added): with SSO mode unset the parser gives no identity and reads no SSO_* value.
  describe 'with SSO mode unset' do
    it 'returns absent even for a valid header and reads no SSO_* getter' do
      allow(SsoMode).to receive(:trusted_proxy_ranges).and_call_original
      allow(SsoMode).to receive(:default_email_domain).and_call_original
      result = parse('a@example.com', env: { 'AUTH_TYPE' => nil, 'SSO_TRUSTED_PROXY_CIDRS' => 'nope', 'DEFAULT_EMAIL_DOMAIN' => 'BAD' })
      expect(result.status).to eq(:absent)
      expect(SsoMode).not_to have_received(:trusted_proxy_ranges)
      expect(SsoMode).not_to have_received(:default_email_domain)
    end
  end
end
