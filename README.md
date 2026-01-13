# SriFacturacion

Biblioteca Ruby para **facturación electrónica en Ecuador (SRI)**.

Incluye utilidades para:

- Generar **clave de acceso** (módulo 11 y código numérico).
- **Firmar XML** (XAdES-BES) a partir de un certificado `.p12`.
- Enviar comprobantes a los servicios SOAP del SRI (recepción / autorización), usando endpoints de pruebas.

> Nota: esta gema es útil como base de integración. Ajusta los endpoints y validaciones según tu ambiente (pruebas/producción) y el tipo de comprobante.

## Instalación

Agrega en tu `Gemfile`:

```ruby
gem "sri_facturacion"
```

Y ejecuta:

```bash
bundle install
```

## Uso

### Orquestación (generar clave, firmar y enviar)

El punto de entrada recomendado es `Sri::InvoiceService::InvoiceOrchestrator`.

```ruby
require "sri/invoice_service"

p12_base64 = File.binread("certificado.p12")
  .then { |bytes| [bytes].pack("m0") } # base64 sin saltos de línea

p12_password = "tu_password"
xml_string   = File.read("tmp/factura.xml")

result = Sri::InvoiceService::InvoiceOrchestrator
  .new(
    p12_base64: p12_base64,
    p12_password: p12_password,
    xml_string: xml_string,
    sequential: 15
  )
  .call

puts result[:clave_acceso]
puts result[:signed_xml_path]
pp result[:recepcion]
pp result[:autorizacion]
```

El hash retornado contiene (entre otros):

- `:clave_acceso`
- `:signed_xml_path` (si el builder persiste el archivo)
- `:recepcion` (respuesta del servicio de recepción)
- `:autorizacion` (respuesta del servicio de autorización)

### Consola

Para probar interactivamente dentro del proyecto:

```bash
bundle exec bin/console
```

O directamente:

```bash
bundle exec irb
```

## Estructura del código

Las piezas principales están bajo `lib/sri/invoice_service/`:

- `access_key_generator.rb` – genera el código numérico y dígito verificador.
- `invoice_builder.rb` – prepara el XML y aplica la firma.
- `invoice_sender.rb` – consume los WSDL del SRI.
- `invoice_orchestrator.rb` – orquesta el flujo completo.

El loader es:

- `lib/sri/invoice_service.rb`

## Desarrollo

- Instalar dependencias:

```bash
bin/setup
```

- Ejecutar tests:

```bash
bundle exec rake spec
```

- Instalar la gema localmente:

```bash
bundle exec rake install
```

## Contribuir

Issues y PRs son bienvenidos.

## Licencia

MIT. Ver `LICENSE.txt`.
