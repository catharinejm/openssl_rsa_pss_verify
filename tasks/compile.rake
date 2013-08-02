require "rake/extensiontask"
load File.expand_path("../rspec.rake", __FILE__)

def gemspec
  @clean_gemspec ||= eval(File.read(File.expand_path('../../openssl_rsa_pss_verify.gemspec', __FILE__)))
end

Rake::ExtensionTask.new("openssl_rsa_pss_verify", gemspec) do |ext|
  ext.lib_dir = File.join 'lib', 'openssl_rsa_pss_verify'
  CLEAN.include "#{ext.lib_dir}/*.#{RbConfig::CONFIG['DLEXT']}"
end
Rake::Task[:spec].prerequisites << :compile
