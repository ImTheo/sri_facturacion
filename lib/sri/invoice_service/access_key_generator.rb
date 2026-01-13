# frozen_string_literal: true

require 'date'
require 'openssl'

module Sri
  module InvoiceService
    class AccessKeyGenerator
      WEIGHTS = [2, 3, 4, 5, 6, 7].freeze

      # Generates an access key from an Nokogiri XML document
      def self.generate!(doc:, sequential:)
        ruc = doc.at_xpath('//infoTributaria/ruc').text.strip
        ambiente = doc.at_xpath('//infoTributaria/ambiente').text.strip
        estab = doc.at_xpath('//infoTributaria/estab').text.strip
        pto_emi = doc.at_xpath('//infoTributaria/ptoEmi').text.strip
        cod_doc = doc.at_xpath('//infoTributaria/codDoc').text.strip
        tipo_emision = doc.at_xpath('//infoTributaria/tipoEmision').text.strip

        fecha_str = doc.at_xpath('//infoFactura/fechaEmision').text.strip
        dd, mm, yyyy = fecha_str.split('/').map(&:to_i)
        fecha = Date.new(yyyy, mm, dd)

        codigo_numerico = random8
        ddmmaaaa = fecha.is_a?(Date) ? fecha.strftime('%d%m%Y') : fecha.to_s
        serie = "#{estab}#{pto_emi}"
        sec9 = sequential.to_s.rjust(9, '0')
        cn8  = codigo_numerico.to_s.rjust(8, '0')

        base48 = "#{ddmmaaaa}#{cod_doc}#{ruc}#{ambiente}#{serie}#{sec9}#{cn8}#{tipo_emision}"
        raise "Base debe ser 48 dígitos, es #{base48.length}" unless base48.length == 48

        base48 + mod11(base48)
      end

      def self.mod11(base48)
        sum = 0
        wi = 0
        base48.reverse.each_char do |ch|
          sum += (ch.ord - 48) * WEIGHTS[wi]
          wi = (wi + 1) % WEIGHTS.length
        end

        dv = 11 - (sum % 11)
        return '0' if dv == 11
        return '1' if dv == 10

        dv.to_s
      end

      def self.random8
        n = OpenSSL::Random.random_bytes(4).unpack1('N') # 0..2^32-1
        (n % 100_000_000).to_s.rjust(8, '0')
      end
    end
  end
end
