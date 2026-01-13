# frozen_string_literal: true

require 'base64'
require 'nokogiri'
require 'open3'
require 'tempfile'
require 'openssl'
require 'securerandom'
require 'time'

module Sri
  module InvoiceService
    # Builds a signed electronic invoice XML for SRI.
    # Responsibilities:
    # - compute access key (claveAcceso)
    # - ensure signature template
    # - sign XML with xmlsec1 using a PKCS#12
    class InvoiceBuilder
      DS_NS = 'http://www.w3.org/2000/09/xmldsig#'
      XADES_NS = 'http://uri.etsi.org/01903/v1.3.2#'

      # @param doc [Nokogiri::XML::Document] Unsigned invoice XML document
      def initialize(doc:, sequential:, p12_base64:, p12_password:, root_id: 'comprobante')
        @doc = doc
        @sequential = sequential
        @p12_base64 = p12_base64
        @p12_password = p12_password
        @root_id = root_id
      end

      def call
        ensure_xmlsec1!

        unsigned_xml = @doc.to_s
        raise 'Debe proporcionar xml_string' if unsigned_xml.strip.empty?

        clave = Sri::InvoiceService::AccessKeyGenerator.generate!(doc: @doc, sequential: @sequential)
        signed_xml = sign_xml(@doc, clave)

        { clave_acceso: clave, signed_xml: signed_xml, signed_xml_path: @last_signed_path }
      end

      private

      def ensure_xmlsec1!
        _out, _err, st = Open3.capture3('xmlsec1', '--version')
        raise 'xmlsec1 no está instalado o no está en PATH' unless st.success?
      end

      def ensure_invoice_root_structure!(doc)
        root = doc.root

        root.name = 'factura' unless root.name == 'factura'
        root['id'] = @root_id if root['id'].to_s.strip.empty?
        root['version'] = '1.1.0' if root['version'].to_s.strip.empty?
      end

      # Minimal XAdES-BES enveloped template for SRI.
      def ensure_signature_template!(doc)
        return if doc.at_xpath('//ds:Signature', 'ds' => DS_NS)

        root = doc.root
        root['id'] ||= @root_id

        signature_id = "Signature-#{SecureRandom.uuid}"
        signed_props_id = "SignedProperties-#{SecureRandom.uuid}"

        sig = Nokogiri::XML::Node.new('ds:Signature', doc)
        sig.add_namespace_definition('ds', DS_NS)
        sig['Id'] = signature_id

        signed_info = Nokogiri::XML::Node.new('ds:SignedInfo', doc)

        canon = Nokogiri::XML::Node.new('ds:CanonicalizationMethod', doc)
        canon['Algorithm'] = 'http://www.w3.org/2001/10/xml-exc-c14n#'

        sig_method = Nokogiri::XML::Node.new('ds:SignatureMethod', doc)
        sig_method['Algorithm'] = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'

        # Reference #1: the root document (enveloped)
        ref_doc = Nokogiri::XML::Node.new('ds:Reference', doc)
        ref_doc['URI'] = "##{@root_id}"

        transforms = Nokogiri::XML::Node.new('ds:Transforms', doc)
        t1 = Nokogiri::XML::Node.new('ds:Transform', doc)
        t1['Algorithm'] = "#{DS_NS}enveloped-signature"
        t2 = Nokogiri::XML::Node.new('ds:Transform', doc)
        t2['Algorithm'] = 'http://www.w3.org/2001/10/xml-exc-c14n#'
        transforms.add_child(t1)
        transforms.add_child(t2)

        digest_method = Nokogiri::XML::Node.new('ds:DigestMethod', doc)
        digest_method['Algorithm'] = 'http://www.w3.org/2001/04/xmlenc#sha256'

        digest_value = Nokogiri::XML::Node.new('ds:DigestValue', doc)
        digest_value.content = ''

        ref_doc.add_child(transforms)
        ref_doc.add_child(digest_method)
        ref_doc.add_child(digest_value)

        # Reference #2: SignedProperties (required for XAdES)
        ref_sp = Nokogiri::XML::Node.new('ds:Reference', doc)
        ref_sp['URI'] = "##{signed_props_id}"
        ref_sp['Type'] = 'http://uri.etsi.org/01903#SignedProperties'

        dm2 = Nokogiri::XML::Node.new('ds:DigestMethod', doc)
        dm2['Algorithm'] = 'http://www.w3.org/2001/04/xmlenc#sha256'
        dv2 = Nokogiri::XML::Node.new('ds:DigestValue', doc)
        dv2.content = ''
        ref_sp.add_child(dm2)
        ref_sp.add_child(dv2)

        signed_info.add_child(canon)
        signed_info.add_child(sig_method)
        signed_info.add_child(ref_doc)
        signed_info.add_child(ref_sp)

        sig_value = Nokogiri::XML::Node.new('ds:SignatureValue', doc)
        sig_value.content = ''

        key_info = Nokogiri::XML::Node.new('ds:KeyInfo', doc)
        x509_data = Nokogiri::XML::Node.new('ds:X509Data', doc)
        key_info.add_child(x509_data)

        # XAdES Object
        obj = Nokogiri::XML::Node.new('ds:Object', doc)

        qp = Nokogiri::XML::Node.new('xades:QualifyingProperties', doc)
        qp.add_namespace_definition('xades', XADES_NS)
        qp['Target'] = "##{signature_id}"

        sp = Nokogiri::XML::Node.new('xades:SignedProperties', doc)
        sp['Id'] = signed_props_id

        ssp = Nokogiri::XML::Node.new('xades:SignedSignatureProperties', doc)

        signing_time = Nokogiri::XML::Node.new('xades:SigningTime', doc)
        signing_time.content = Time.now.utc.iso8601

        signing_cert = Nokogiri::XML::Node.new('xades:SigningCertificate', doc)
        cert_node = Nokogiri::XML::Node.new('xades:Cert', doc)

        cert_digest = Nokogiri::XML::Node.new('xades:CertDigest', doc)
        dm = Nokogiri::XML::Node.new('ds:DigestMethod', doc)
        dm['Algorithm'] = 'http://www.w3.org/2001/04/xmlenc#sha256'
        dv = Nokogiri::XML::Node.new('ds:DigestValue', doc)
        dv.content = ''
        cert_digest.add_child(dm)
        cert_digest.add_child(dv)

        issuer_serial = Nokogiri::XML::Node.new('xades:IssuerSerial', doc)
        x509_issuer = Nokogiri::XML::Node.new('ds:X509IssuerName', doc)
        x509_serial = Nokogiri::XML::Node.new('ds:X509SerialNumber', doc)
        x509_issuer.content = ''
        x509_serial.content = ''
        issuer_serial.add_child(x509_issuer)
        issuer_serial.add_child(x509_serial)

        cert_node.add_child(cert_digest)
        cert_node.add_child(issuer_serial)
        signing_cert.add_child(cert_node)

        ssp.add_child(signing_time)
        ssp.add_child(signing_cert)

        sp.add_child(ssp)
        qp.add_child(sp)
        obj.add_child(qp)

        sig.add_child(signed_info)
        sig.add_child(sig_value)
        sig.add_child(key_info)
        sig.add_child(obj)

        root.add_child(sig)

        @signature_id = signature_id
        @signed_properties_id = signed_props_id
      end

      def inject_access_key!(doc, clave_acceso)
        return if clave_acceso.to_s.strip.empty?

        root = doc.root
        info_tributaria = root.at_xpath('./infoTributaria') || root.at_xpath('//infoTributaria')

        unless info_tributaria
          info_tributaria = Nokogiri::XML::Node.new('infoTributaria', doc)
          if root.children.any?
            root.children.first.add_previous_sibling(info_tributaria)
          else
            root.add_child(info_tributaria)
          end
        end

        clave_node = info_tributaria.at_xpath('./claveAcceso')
        clave_node ||= Nokogiri::XML::Node.new('claveAcceso', doc)
        clave_node.content = clave_acceso.to_s
        ruc_node = info_tributaria.at_xpath('./ruc')
        cod_doc_node = info_tributaria.at_xpath('./codDoc')

        if ruc_node
          clave_node.remove if clave_node.parent
          ruc_node.add_next_sibling(clave_node)
        elsif cod_doc_node
          clave_node.remove if clave_node.parent
          cod_doc_node.add_previous_sibling(clave_node)
        else
          info_tributaria.add_child(clave_node) unless clave_node.parent
        end
        nodes = info_tributaria.xpath('./claveAcceso')
        nodes.drop(1).each(&:remove) if nodes.size > 1
      end

      def inject_secuencial!(doc)
        sec = @sequential.to_s.rjust(9, '0')

        info_tributaria = doc.root.at_xpath('./infoTributaria') || doc.at_xpath('//infoTributaria')
        return unless info_tributaria

        sec_node = info_tributaria.at_xpath('./secuencial')
        sec_node ||= Nokogiri::XML::Node.new('secuencial', doc)
        sec_node.content = sec

        pto_emi_node = info_tributaria.at_xpath('./ptoEmi')
        if pto_emi_node
          sec_node.remove if sec_node.parent
          pto_emi_node.add_next_sibling(sec_node)
        else
          info_tributaria.add_child(sec_node) unless sec_node.parent
        end

        # Remove duplicates
        nodes = info_tributaria.xpath('./secuencial')
        nodes.drop(1).each(&:remove) if nodes.size > 1
      end

      def sign_xml(doc, clave_acceso)
        ensure_invoice_root_structure!(doc)
        ensure_signature_template!(doc)

        inject_access_key!(doc, clave_acceso)
        inject_secuencial!(doc)

        p12_path = resolve_p12_path!
        validate_pkcs12!(p12_path)

        inject_cert_chain_and_xades_data!(doc, p12_path)

        root_name = doc.root.name
        input_xml = doc.to_xml

        Tempfile.create(%w[sri_unsigned .xml]) do |in_xml|
          in_xml.write(input_xml)
          in_xml.flush

          Tempfile.create(%w[sri_signed .xml]) do |out_xml|
            cmd = [
              'xmlsec1', '--sign',
              '--pkcs12', p12_path,
              '--id-attr:id', root_name,
              '--output', out_xml.path,
              in_xml.path
            ]

            if @p12_password && !@p12_password.to_s.empty?
              cmd.insert(4, '--pwd')
              cmd.insert(5, @p12_password)
            end

            _stdout, stderr, status = Open3.capture3(*cmd)
            raise "Fallo firmando con xmlsec1: #{stderr.to_s.strip}" unless status.success?

            @last_signed_path = out_xml.path.dup
            File.read(out_xml.path)
          end
        end
      end

      def inject_cert_chain_and_xades_data!(doc, p12_path)
        pkcs12 = OpenSSL::PKCS12.new(File.binread(p12_path), @p12_password.to_s)
        leaf = pkcs12.certificate
        chain = Array(pkcs12.ca_certs)

        x509_data = doc.at_xpath('//ds:Signature/ds:KeyInfo/ds:X509Data', 'ds' => DS_NS)
        raise 'No se encontró ds:X509Data para inyectar certificados' unless x509_data

        x509_data.children.remove
        ([leaf] + chain).compact.each do |cert|
          n = Nokogiri::XML::Node.new('ds:X509Certificate', doc)
          n.content = Base64.strict_encode64(cert.to_der)
          x509_data.add_child(n)
        end

        digest_value_node = doc.at_xpath('//xades:SigningCertificate//xades:CertDigest/ds:DigestValue',
                                         'xades' => XADES_NS, 'ds' => DS_NS)
        issuer_node = doc.at_xpath('//xades:SigningCertificate//xades:IssuerSerial/ds:X509IssuerName',
                                   'xades' => XADES_NS, 'ds' => DS_NS)
        serial_node = doc.at_xpath('//xades:SigningCertificate//xades:IssuerSerial/ds:X509SerialNumber',
                                   'xades' => XADES_NS, 'ds' => DS_NS)

        digest_value_node.content = Base64.strict_encode64(OpenSSL::Digest::SHA256.digest(leaf.to_der)) if digest_value_node
        issuer_node.content = leaf.issuer.to_s(OpenSSL::X509::Name::RFC2253) if issuer_node
        serial_node.content = leaf.serial.to_s if serial_node
      end

      def validate_pkcs12!(p12_path)
        passin = if @p12_password && !@p12_password.to_s.empty?
                   "pass:#{@p12_password}"
                 else
                   'pass:'
                 end

        cmd = ['openssl', 'pkcs12', '-in', p12_path, '-noout', '-passin', passin]
        _out, err, st = Open3.capture3(*cmd)
        return if st.success?

        raise "Certificado PKCS#12 inválido o password incorrecta (openssl): #{err.to_s.strip}"
      end

      def resolve_p12_path!
        raise 'Debe proporcionar p12_base64' if @p12_base64.to_s.strip.empty?

        tmp = Tempfile.create(%w[sri_p12 .p12])
        tmp.binmode
        tmp.write(Base64.strict_decode64(@p12_base64))
        tmp.flush
        tmp.close

        @tmp_p12_file = tmp
        tmp.path
      rescue ArgumentError => e
        raise "p12_base64 inválido (base64): #{e.message}"
      end
    end
  end
end
