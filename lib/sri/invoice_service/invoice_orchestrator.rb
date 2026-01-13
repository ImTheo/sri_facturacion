# frozen_string_literal: true

require 'nokogiri'

module Sri
  module InvoiceService
    # Orchestrates: build access key + sign + send to SRI sandbox endpoints.
    # Implementation details are delegated to:
    # - Sri::InvoiceService::InvoiceBuilder
    # - Sri::InvoiceService::InvoiceSender
    class InvoiceOrchestrator
      RECEPCION_WSDL = 'https://celcer.sri.gob.ec/comprobantes-electronicos-ws/RecepcionComprobantesOffline?wsdl'
      AUTORIZACION_WSDL = 'https://celcer.sri.gob.ec/comprobantes-electronicos-ws/AutorizacionComprobantesOffline?wsdl'
      DS_NS = 'http://www.w3.org/2000/09/xmldsig#'
      XADES_NS = 'http://uri.etsi.org/01903/v1.3.2#'

      def initialize(p12_base64:, p12_password:, xml_string:, sequential:, root_id: 'comprobante')
        @p12_base64 = p12_base64
        @p12_password = p12_password
        @xml_string = xml_string
        @root_id = root_id
        @sequential = sequential
      end

      def call
        unsigned_xml = @xml_string.to_s
        raise 'Debe proporcionar xml_string' if unsigned_xml.strip.empty?

        doc = Nokogiri::XML(@xml_string.to_s) { |cfg| cfg.strict.noblanks }
        environment = doc.at_xpath('//infoTributaria/ambiente').text.strip
        builder = Sri::InvoiceService::InvoiceBuilder.new(
          doc:,
          sequential: @sequential,
          p12_base64: @p12_base64,
          p12_password: @p12_password,
          root_id: @root_id
        )

        built = builder.call

        sender = Sri::InvoiceService::InvoiceSender.new(environment:)
        sent = sender.call(clave_acceso: built.fetch(:clave_acceso), signed_xml: built.fetch(:signed_xml))

        {
          clave_acceso: built.fetch(:clave_acceso),
          signed_xml_path: built[:signed_xml_path],
          recepcion: sent.fetch(:recepcion),
          autorizacion: sent.fetch(:autorizacion)
        }
      end
    end
  end
end
