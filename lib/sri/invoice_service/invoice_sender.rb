# frozen_string_literal: true

require 'base64'
require 'savon'

module Sri
  module InvoiceService
    # Sends a signed invoice XML to SRI sandbox endpoints.
    class InvoiceSender
      TEST_RECEPTION_WSDL = 'https://celcer.sri.gob.ec/comprobantes-electronicos-ws/RecepcionComprobantesOffline?wsdl'
      TEST_AUTHORIZATION_WSDL = 'https://celcer.sri.gob.ec/comprobantes-electronicos-ws/AutorizacionComprobantesOffline?wsdl'

      PRODUCTION_RECEPTION_WSDL = 'https://cel.sri.gob.ec/comprobantes-electronicos-ws/RecepcionComprobantesOffline?wsdl'
      PRODUCTION_AUTHORIZATION_WSDL = 'https://cel.sri.gob.ec/comprobantes-electronicos-ws/AutorizacionComprobantesOffline?wsdl'

      TEST_ENVIRONMENT = 1
      PRODUCTION_ENVIRONMENT = 2

      def initialize(reception_client: nil, authorization_client: nil, environment: 1)
        @reception_client = reception_client
        @authorization_client = authorization_client
        @environment = environment == PRODUCTION_ENVIRONMENT ? PRODUCTION_ENVIRONMENT : TEST_ENVIRONMENT
      end

      def call(clave_acceso:, signed_xml:)
        recep = reception_client.call(
          :validar_comprobante,
          headers: { 'SOAPAction' => '""' },
          message: { 'xml' => Base64.strict_encode64(signed_xml.to_s) }
        ).body

        recep_parsed = parse_recepcion(recep)

        auth = authorization_client.call(
          :autorizacion_comprobante,
          headers: { 'SOAPAction' => '""' },
          message: { 'claveAccesoComprobante' => clave_acceso }
        ).body

        auth_parsed = parse_autorizacion(auth)

        {
          recepcion: recep_parsed.merge(raw: recep),
          autorizacion: auth_parsed.merge(raw: auth)
        }
      end

      private

      def reception_client
        wsdl = @environment == :production ? PRODUCTION_RECEPTION_WSDL : TEST_RECEPTION_WSDL
        @reception_client ||= Savon.client(
          wsdl:,
          convert_request_keys_to: :none,
          open_timeout: 10,
          read_timeout: 30,
          log: false
        )
      end

      def authorization_client
        wsdl = @environment == :production ? PRODUCTION_AUTHORIZATION_WSDL : TEST_AUTHORIZATION_WSDL
        @authorization_client ||= Savon.client(
          wsdl:,
          convert_request_keys_to: :none,
          open_timeout: 10,
          read_timeout: 30,
          log: false
        )
      end

      def parse_recepcion(body)
        resp = dig_any(body, :validarComprobanteResponse, :validar_comprobante_response) || body
        rr = dig_any(resp, :RespuestaRecepcionComprobante, :respuesta_recepcion_comprobante) || resp

        estado = dig_any(rr, :estado) || dig_any(resp, :estado)
        mensajes = extract_mensajes(dig_any(rr, :comprobantes, :comprobante) || rr)

        { estado: estado, mensajes: mensajes }
      end

      def parse_autorizacion(body)
        resp = dig_any(body, :autorizacionComprobanteResponse, :autorizacion_comprobante_response) || body
        ra = dig_any(resp, :RespuestaAutorizacionComprobante, :respuesta_autorizacion_comprobante) || resp

        auts = dig_any(ra, :autorizaciones, :autorizacion) || []
        aut = auts.is_a?(Array) ? auts.first : auts

        estado = dig_any(aut, :estado) || dig_any(ra, :estado)
        mensajes = extract_mensajes(aut || ra)

        { estado: estado, mensajes: mensajes }
      end

      def extract_mensajes(node)
        msgs = dig_any(node, :mensajes, :mensaje) || dig_any(node, :mensajes) || []
        msgs = [msgs] if msgs.is_a?(Hash)
        msgs = Array(msgs)

        msgs.map do |m|
          [
            dig_any(m, :identificador),
            dig_any(m, :mensaje),
            dig_any(m, :informacionAdicional, :informacion_adicional),
            dig_any(m, :tipo)
          ].compact.join(' | ')
        end
      rescue StandardError
        []
      end

      def dig_any(obj, *keys)
        keys.each do |k|
          v = obj.is_a?(Hash) ? (obj[k] || obj[k.to_s]) : nil
          return v unless v.nil?
        end
        nil
      end
    end
  end
end
