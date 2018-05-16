<?php

namespace Banklink\Protocol;

use Banklink\Protocol\Citadele\Fields,
    Banklink\Protocol\Citadele\Services;

use Banklink\Response\PaymentResponse;
use Banklink\Response\AuthResponse;

use Banklink\Protocol\Util\ProtocolUtils;

use Banklink\Response\Response;
use RobRichards\XMLSecLibs\XMLSecEnc;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

class CitadeleProtocol implements ProtocolInterface
{
    protected $publicKey;
    protected $privateKey;

    protected $fromId;              // from
    protected $sellerId;            // account_owner_id
    protected $sellerName;          // account_owner
    protected $sellerAccountNumber; // account_number

    protected $endpointUrl;

    /**
     * Initialize basic data that will be used for all issued service requests
     *
     * @param string $sellerId
     * @param string $fromId
     * @param string $sellerName
     * @param integer $sellerAccNum
     * @param string $privateKey Private key location
     * @param string $publicKey Public key (certificate) location
     * @param string $endpointUrl
     */
    public function __construct($sellerId, $fromId, $sellerName, $sellerAccNum, $privateKey, $publicKey, $endpointUrl)
    {
        $this->sellerId = $sellerId;
        $this->fromId = $fromId;
        $this->sellerName = $sellerName;
        $this->sellerAccountNumber = $sellerAccNum;
        $this->endpointUrl = $endpointUrl;

        $this->publicKey = $publicKey;
        $this->privateKey = $privateKey;
    }

    /**
     * @param integer $orderId
     * @param float $sum
     * @param string $message
     * @param string $outputEncoding
     * @param string $language
     * @param string $currency
     *
     * @return array
     */
    public function preparePaymentRequestData(
        $orderId,
        $sum,
        $message,
        $outputEncoding,
        $language = 'EST',
        $currency = 'EUR'
    ) {
        $xml = new \XMLWriter();
        $datetime = new \DateTime('now', new \DateTimeZone('Europe/Tallinn'));

        $xml->openMemory();
        $xml->startDocument('1.0', 'UTF-8');
        $xml->setIndent(4);
        $xml->startElement('FIDAVISTA');
        $xml->writeAttribute('xmlns', 'http://ivis.eps.gov.lv/XMLSchemas/100017/fidavista/v1-2');
        $xml->writeAttribute('xmlns:xsi', 'http://www.w3.org/2001/XMLSchemainstance');
        $xml->writeAttribute(
            'xsi:schemaLocation',
            'http://ivis.eps.gov.lv/XMLSchemas/100017/fidavista/v1-2 http://ivis.eps.gov.lv/XMLSchemas/100017/fidavista/v1-2/fidavista.xsd'
        );

        $xml->startElement('Header');
        $xml->writeElement('From', $this->fromId);
        $xml->writeElement('Timestamp', substr($datetime->format('YmdHisu'), 0, 17));

        $xml->startElement('Extension');
        $xml->startElement('Amai');
        $xml->writeAttribute('xmlns', 'http://online.citadele.lv/XMLSchemas/amai/');
        $xml->writeAttribute('xmlns:xsi', 'http://www.w3.org/2001/XMLSchema-instance');
        $xml->writeAttribute(
            'xsi:schemaLocation',
            'http://online.citadele.lv/XMLSchemas/amai/ http://online.citadele.lv/XMLSchemas/amai/amai.xsd'
        );

        $xml->writeElement('Request', Services::PAYMENT_REQUEST);
        $xml->writeElement('RequestUID', uniqid($orderId, true));
        $xml->writeElement('Version', '3.0');
        $xml->writeElement('Language', $language);
        $xml->writeElement('ReturnURL', $this->endpointUrl);
        $xml->writeElement('SignatureData');    // placeholder for the signature
        $xml->endElement(); // Amai
        $xml->endElement(); // Extension
        $xml->endElement(); // Header

        $xml->startElement('PaymentRequest');
        $xml->writeElement('PmtInfo', $message);
        $xml->writeElement('Ccy', $currency);
        $xml->writeElement('DocNo', $orderId);
        $xml->writeElement('ExtId', $orderId);
        $xml->writeElement('TaxPmtFlg', 'N');

        $xml->startElement('BenSet');
        $xml->writeElement('Amt', $sum);
        $xml->writeElement('Comm', 'OUR');
        $xml->writeElement('Priority', 'N');
        $xml->writeElement('BenAccNo', $this->sellerAccountNumber);
        $xml->writeElement('BenName', $this->sellerName);
        $xml->writeElement('BenLegalId', $this->sellerId);
        $xml->writeElement('BenCountry', 'LV');

        $xml->endElement(); // BenSet
        $xml->endElement(); // PaymentRequest
        $xml->endElement(); // FIDAVISTA
        $xml->endDocument();
        $xmlString = $xml->outputMemory();

        $doc = new \DOMDocument();
        $doc->loadXML($xmlString);

        $objKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, array('type' => 'private'));
        $objKey->loadKey($this->privateKey);

        $objDSig = new XMLSecurityDSig();
        $objDSig->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);
        $objDSig->addReference(
            $doc,
            XMLSecurityDSig::SHA256,
            array('http://www.w3.org/2000/09/xmldsig#enveloped-signature'),
            array('force_uri' => true)
        );
        $objDSig->sign($objKey);
        $objDSig->add509Cert($this->publicKey);

        $appendSignatureTo = $doc->getElementsByTagName('SignatureData')->item(0);
        $objDSig->appendSignature($appendSignatureTo);
        $xml = $doc->saveXML();

//        exit( var_dump($this->verify($xml)) );
        $xml = str_replace(["\n", "\t", "\r", "\r\n", '&amp;', '"'], ['', '', '', '', '&amp;amp;', '&quot;'], $xml);

        return [
            Fields::XML_DATA => $xml,
        ];
    }

    public function prepareAuthRequestData($language)
    {
        $xml = new \XMLWriter();
        $datetime = new \DateTime('now', new \DateTimeZone('Europe/Tallinn'));

        $xml->openMemory();
        $xml->startDocument('1.0', 'UTF-8');
        $xml->setIndent(4);
        $xml->startElement('FIDAVISTA');
        $xml->writeAttribute('xmlns', 'http://ivis.eps.gov.lv/XMLSchemas/100017/fidavista/v1-2');
        $xml->writeAttribute('xmlns:xsi', 'http://www.w3.org/2001/XMLSchemainstance');
        $xml->writeAttribute(
            'xsi:schemaLocation',
            'http://ivis.eps.gov.lv/XMLSchemas/100017/fidavista/v1-2 http://ivis.eps.gov.lv/XMLSchemas/100017/fidavista/v1-2/fidavista.xsd'
        );

        $xml->startElement('Header');
        $xml->writeElement('Timestamp', substr($datetime->format('YmdHisu'), 0, 17));
        $xml->writeElement('From', $this->fromId);

        $xml->startElement('Extension');
        $xml->startElement('Amai');
        $xml->writeAttribute('xmlns', 'http://online.citadele.lv/XMLSchemas/amai/');
        $xml->writeAttribute('xmlns:xsi', 'http://www.w3.org/2001/XMLSchema-instance');
        $xml->writeAttribute(
            'xsi:schemaLocation',
            'http://online.citadele.lv/XMLSchemas/amai/ http://online.citadele.lv/XMLSchemas/amai/amai.xsd'
        );

        $xml->writeElement('Request', Services::AUTHENTICATE_REQUEST);
        $xml->writeElement('RequestUID', $this->guidv4(random_bytes(16)));
        $xml->writeElement('Version', '5.0');
        $xml->writeElement('Language', $language);
        $xml->writeElement('ReturnURL', $this->endpointUrl);
        $xml->writeElement('SignatureData');    // placeholder for the signature
        $xml->endElement(); // Amai
        $xml->endElement(); // Extension
        $xml->endElement(); // Header
        $xml->endElement(); // FIDAVISTA
        $xml->endDocument();
        $xmlString = $xml->outputMemory();

        $doc = new \DOMDocument();
        $doc->loadXML($xmlString);

        $objKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA1, array('type' => 'private'));
        $objKey->loadKey($this->privateKey);

        $objDSig = new XMLSecurityDSig();
        $objDSig->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);
        $objDSig->addReference(
            $doc,
            XMLSecurityDSig::SHA1,
            array('http://www.w3.org/2000/09/xmldsig#enveloped-signature'),
            array('force_uri' => true)
        );
        $objDSig->sign($objKey);
        $objDSig->add509Cert($this->publicKey);

        $appendSignatureTo = $doc->getElementsByTagName('SignatureData')->item(0);
        $objDSig->appendSignature($appendSignatureTo);
        $xml = $doc->saveXML();

        $xml = str_replace(['&amp;', '"'], ['&amp;amp;', '&quot;'], $xml);

        return [
            Fields::XML_DATA => $xml,
        ];

        return $requestData;
    }

    private function guidv4($data)
    {
        assert(strlen($data) == 16);

        $data[6] = chr(ord($data[6]) & 0x0f | 0x40); // set version to 0100
        $data[8] = chr(ord($data[8]) & 0x3f | 0x80); // set bits 6-7 to 10

        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
    }

    /**
     * Determine which response exactly by service id, if it's supported then call related internal method
     *
     * @param array $responseData
     * @param string $inputEncoding
     *
     * @return \Banklink\Response\Response
     *
     * @throws \InvalidArgumentException
     */
    public function handleResponse(array $responseData, $inputEncoding)
    {

        $verificationSuccess = $this->verifyResponseSignature($responseData, $inputEncoding);

        $responseData = ProtocolUtils::convertValues($responseData, $inputEncoding, 'UTF-8');

        $doc = new \DOMDocument();
        $doc->loadXML($responseData['xmldata']);

        if (200 == $doc->getElementsByTagName('Code')[0]->nodeValue) {
            return new Response(0, []);
        }

        $responseData = [
            'request' => $doc->getElementsByTagName('Request')[0]->nodeValue,
            'personalCode' => $doc->getElementsByTagName('PersonCode')[0]->nodeValue,
            'person' => $doc->getElementsByTagName('Person')[0]->nodeValue,
            'code' => $doc->getElementsByTagName('Code')[0]->nodeValue,
        ];

        $service = $responseData[Fields::SERVICE_ID];
        // TODO: Payment processing
        /*if (in_array($service, Services::getPaymentServices())) {
            return $this->handlePaymentResponse($responseData, $verificationSuccess);
        }*/
        if (in_array($service, Services::getAuthenticationServices())) {
            return $this->handleAuthResponse($responseData, $verificationSuccess);
        }

        throw new \InvalidArgumentException('Unsupported service with id: '.$service);
    }

    /**
     * Verify that response data is correctly signed
     *
     * @param array $responseData
     * @param string $encoding Response data encoding
     *
     * @return boolean
     */
    protected function verifyResponseSignature(array $responseData, $encoding)
    {
        $doc = new \DOMDocument();
        $doc->loadXML($responseData['xmldata']);
        $objXMLSecDSig = new XMLSecurityDSig();

        if (!$objDSig = $objXMLSecDSig->locateSignature($doc)) {
            throw new \Exception('Cannot locate Signature Node');
        }
        $objXMLSecDSig->canonicalizeSignedInfo();
        $objXMLSecDSig->idKeys = ['wsu:Id'];
        $objXMLSecDSig->idNS = ['wsu' => 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd'];

        try {
            $retVal = $objXMLSecDSig->validateReference();
        } catch (\Exception $e) {
            return null;
        }

        if (!$objKey = $objXMLSecDSig->locateKey()) {
            return null;
        }

        $key = null;

        $objKeyInfo = XMLSecEnc::staticLocateKeyInfo($objKey, $objDSig);

        return $objXMLSecDSig->verify($objKey) === 1;
    }

    public function handleAuthResponse(array $responseData, $verificationSuccess)
    {
        // if response was verified, try to guess status by service id


        if ($verificationSuccess) {
            $status = $responseData[Fields::SERVICE_STATUS] == Services::AUTHENTICATE_SUCCESS ? PaymentResponse::STATUS_SUCCESS : PaymentResponse::STATUS_CANCEL;
        } else {
            $status = PaymentResponse::STATUS_ERROR;
        }

        $response = new AuthResponse($status, $responseData);

        if (AuthResponse::STATUS_SUCCESS === $status) {
            $infoField = explode(' ', $responseData[Fields::VK_INFO]);
            $response->setPersonalCode(substr_replace($responseData[Fields::VK_USER], '-', 6, 0));
            $response->setFirstname(trim($infoField[0]));
            $response->setLastname(trim($infoField[1]));

        }

        return $response;
    }

    /**
     * Prepare payment response instance
     * Some data is only set if response is succesful
     *
     * @param array $responseData
     *
     * @return \Banklink\Response\PaymentResponse
     */
    protected function handlePaymentResponse(array $responseData, $verificationSuccess)
    {
        // if response was verified, try to guess status by service id
        if ($verificationSuccess) {
            $status = $responseData[Fields::SERVICE_ID] == Services::PAYMENT_SUCCESS ? PaymentResponse::STATUS_SUCCESS : PaymentResponse::STATUS_CANCEL;
        } else {
            $status = PaymentResponse::STATUS_ERROR;
        }

        $response = new PaymentResponse($status, $responseData);
        $response->setOrderId($responseData[Fields::ORDER_ID]);

        if (PaymentResponse::STATUS_SUCCESS === $status) {
            $response->setSum($responseData[Fields::SUM]);
            $response->setCurrency($responseData[Fields::CURRENCY]);
            $response->setSenderName($responseData[Fields::SENDER_NAME]);
            $response->setSenderBankAccount($responseData[Fields::SENDER_BANK_ACC]);
            $response->setTransactionId($responseData[Fields::TRANSACTION_ID]);
            $response->setTransactionDate(new \DateTime($responseData[Fields::TRANSACTION_DATE]));
        }

        return $response;
    }

    /**
     * Generate request signature built with mandatory request data and private key
     *
     * @param array $data
     * @param string $encoding
     *
     * @return string
     */
    protected function getRequestSignature($fields)
    {
        $hash = $this->generateHash($fields);

        $keyId = openssl_get_privatekey($this->privateKey);
        openssl_sign($hash, $signature, $keyId);
        openssl_free_key($keyId);

        $result = base64_encode($signature);

        return $result;
    }

    /**
     * Generate request/response hash based on mandatory fields
     *
     * @param array $data
     * @param string $encoding Data encoding
     *
     * @return string
     *
     * @throws \LogicException
     */
    protected function generateHash(array $data, $encoding = 'UTF-8')
    {
        $id = $data[Fields::SERVICE_ID];

        $hash = '';

        foreach (Services::getFieldsForService($id) as $fieldName) {
            if (!isset($data[$fieldName])) {
                throw new \LogicException(sprintf('Cannot generate %s service hash without %s field', $id, $fieldName));
            }

            $content = $data[$fieldName];
            if ($this->mbStrlen) {
                $hash .= str_pad(mb_strlen($content, $encoding), 3, "0", STR_PAD_LEFT).$content;
            } else {
                $hash .= str_pad(strlen($content), 3, "0", STR_PAD_LEFT).$content;
            }
        }

        return $hash;
    }

    private function verify($xml)
    {
        $doc = new \DOMDocument();
        $doc->loadXML($xml);
        $objXMLSecDSig = new XMLSecurityDSig();

        if (!$objDSig = $objXMLSecDSig->locateSignature($doc)) {
            throw new \Exception("Cannot locate Signature Node");
        }
        $objXMLSecDSig->canonicalizeSignedInfo();
        $objXMLSecDSig->idKeys = array('wsu:Id');
        $objXMLSecDSig->idNS = array('wsu' => 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd');

        if (!$retVal = $objXMLSecDSig->validateReference()) {
            throw new \Exception("Reference Validation Failed");
        }

        if (!$objKey = $objXMLSecDSig->locateKey()) {
            throw new \Exception("We have no idea about the key");
        }

        $objKey->loadKey($this->publicKey);

        return $objXMLSecDSig->verify($objKey);

    }
}