# with thanks to the github-markup and sinatra gemspecs, for
# sorting me out.

Gem::Specification.new do |s|
  s.name = 'fail'
  s.version = '0.0.1'
  s.author = 'Edd Steel'
  s.date = Time.now.strftime('%Y-%m-%d')
  s.summary = "Facebook Application Integration Layer"
  s.homepage = "http://github.com/eddsteel/fail"
  s.email = "edward.steel@gmail.com"
  s.has_rdoc = false
  s.description = "Provides painless access to the Facebook
  'REST' API. Its name is in no way a reflection of that API's
  design."
  s.files = %w( README.md LICENSE )
  s.files += Dir.glob("lib/**/*")
  s.rdoc_options = ["--line-numbers", "--inline-source", "--title", "F A I L", "-c", "utf-8", "--all"]
end
