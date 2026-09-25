# Parses the X-Auth-Request-Email header set by the edge proxy. The header is uncontrolled input,
# so parsing is strict, never raises, and uses no regex on unbounded input (only on <= 254 bytes
# after the length check). Only called in SSO mode; callers map :unusable to a 401 or a flush.
class ProxyAuth::Identity
  HEADER = 'X-Auth-Request-Email'.freeze
  MAX_BYTES = 254
  LOCAL_PART = /\A[a-z0-9._+-]{1,64}\z/
  LABEL = /\A[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\z/
  TLD = /\A[a-z]{2,24}\z/

  Result = Data.define(:status, :email)

  def self.from_request(request)
    new(request).parse
  end

  def initialize(request)
    @request = request
  end

  def parse
    # ponytail: mode-off guard is defence in depth; callers must already gate on SsoMode.enabled?
    return absent unless SsoMode.enabled? && trusted_peer?

    raw = @request.headers[HEADER]
    raw.is_a?(String) ? normalise(raw) : absent
  rescue StandardError
    unusable
  end

  private

  def normalise(raw)
    return unusable unless raw.valid_encoding?

    value = raw.strip
    return absent if value.empty?
    return unusable if value.bytesize > MAX_BYTES || !value.ascii_only?

    email = build_email(value.downcase)
    email ? Result.new(status: :present, email: email) : unusable
  end

  def absent
    Result.new(status: :absent, email: nil)
  end

  def unusable
    Result.new(status: :unusable, email: nil)
  end

  def trusted_peer?
    ranges = SsoMode.trusted_proxy_ranges
    return true if ranges.empty?

    peer = IPAddr.new(@request.env['REMOTE_ADDR'].to_s)
    ranges.any? { |range| range.include?(peer) }
  rescue IPAddr::Error
    false
  end

  def build_email(value)
    local, domain = split_address(value)
    return unless local && domain && local.match?(LOCAL_PART) && valid_domain?(domain)

    "#{local}@#{domain}"
  end

  # Shape checks use index (O(n)), never a regex on unbounded input. Returns [local, domain] or nil.
  def split_address(value)
    at = value.index('@')
    return [value, SsoMode.default_email_domain] if at.nil?
    return if at.zero? || value.index('@', at + 1)

    dot = value.index('.', at + 1)
    return if dot.nil? || dot == at + 1

    [value[0...at], value[(at + 1)..]]
  end

  def valid_domain?(domain)
    labels = domain.split('.', -1)
    labels.size >= 2 && labels.all? { |label| label.match?(LABEL) } && labels.last.match?(TLD)
  end
end
