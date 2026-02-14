# frozen_string_literal: true

# app/services/sri/constants.rb

module Sri
  module Constants
    TEST_RECEPTION_WSDL = 'https://celcer.sri.gob.ec/comprobantes-electronicos-ws/RecepcionComprobantesOffline?wsdl'
    TEST_AUTHORIZATION_WSDL = 'https://celcer.sri.gob.ec/comprobantes-electronicos-ws/AutorizacionComprobantesOffline?wsdl'

    PRODUCTION_RECEPTION_WSDL = 'https://cel.sri.gob.ec/comprobantes-electronicos-ws/RecepcionComprobantesOffline?wsdl'
    PRODUCTION_AUTHORIZATION_WSDL = 'https://cel.sri.gob.ec/comprobantes-electronicos-ws/AutorizacionComprobantesOffline?wsdl'

    TEST_ENVIRONMENT = 1
    PRODUCTION_ENVIRONMENT = 2

    PROD = {
      recepcion_wsdl: PRODUCTION_RECEPTION_WSDL,
      autorizacion_wsdl: PRODUCTION_AUTHORIZATION_WSDL
    }.freeze

    TEST = {
      recepcion_wsdl: TEST_RECEPTION_WSDL,
      autorizacion_wsdl: TEST_AUTHORIZATION_WSDL
    }.freeze
  end
end
