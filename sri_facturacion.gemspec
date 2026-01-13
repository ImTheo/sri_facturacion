# frozen_string_literal: true

require_relative "lib/sri_facturacion/version"

Gem::Specification.new do |spec|
  spec.name = "sri_facturacion"
  spec.version = SriFacturacion::VERSION
  spec.summary = "Facturación electrónica SRI (firma y envío)"
  spec.description = "Firma XAdES-BES y envío a SRI."
  spec.authors = ["Theo Rosero"]
  spec.email = ["theomrosero@gmail.com"]
  spec.files = Dir["lib/**/*", "README.md", "LICENSE.txt"]
  spec.license = "MIT"
  spec.require_paths = ["lib"]

  spec.metadata = {
    "homepage_uri" => "https://github.com/ImTheo/sri_facturacion",
    "source_code_uri" => "https://github.com/ImTheo/sri_facturacion",
    "changelog_uri" => "https://github.com/ImTheo/sri_facturacion/blob/main/CHANGELOG.md"
  }

  spec.required_ruby_version = ">= 3.0"

  spec.add_dependency "net-http", ">= 0.4"
  spec.add_dependency "nokogiri", ">= 1.14"
  spec.add_dependency "savon", ">= 2.15"

end
