require 'rails_helper'

RSpec.describe 'SsoMode single predicate' do # rubocop:disable RSpec/DescribeClass
  it 'is read from AUTH_TYPE only in config/initializers/00_sso_mode.rb' do
    globs = %w[app lib config enterprise].map { |dir| Rails.root.join(dir, '**', '*.rb').to_s }
    readers = Dir.glob(globs).select { |f| File.read(f).include?('AUTH_TYPE') }
    expect(readers.map { |f| Pathname.new(f).relative_path_from(Rails.root).to_s }).to eq(['config/initializers/00_sso_mode.rb'])
  end
end
