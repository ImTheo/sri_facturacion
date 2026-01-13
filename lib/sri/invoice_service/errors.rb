# frozen_string_literal: true

module Sri
  module InvoiceService
    class Error < StandardError; end
    class MissingXmlError < Error; end
    class XmlsecNotInstalledError < Error; end
    class InvalidPkcs12Error < Error; end
    class SoapError < Error; end
  end
end
