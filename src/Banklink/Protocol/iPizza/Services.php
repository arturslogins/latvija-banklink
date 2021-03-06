<?php

namespace Banklink\Protocol\iPizza;

/**
 * List of all services available via iPizza
 *
 * @author Roman Marintsenko <inoryy@gmail.com>
 * @since  10.01.2012
 */
final class Services
{
    // Requests
    const PAYMENT_REQUEST      = '1012';
    const AUTHENTICATE_REQUEST = '4011';

    // Responses
    const PAYMENT_SUCCESS      = '1111';
    const PAYMENT_CANCEL       = '1911';
    const PAYMENT_ERROR        = '1911';
    const AUTHENTICATE_SUCCESS = '3012';

    /**
     * Fetch mandatory fields for a given service
     *
     * @param string $serviceId
     * @return array
     * @throws \InvalidArgumentException
     */
    public static function getFieldsForService($serviceId)
    {
        switch ($serviceId) {
            case Services::PAYMENT_REQUEST:
                return array(
                    Fields::SERVICE_ID,
                    Fields::PROTOCOL_VERSION,
                    Fields::SELLER_ID,
                    Fields::ORDER_ID,
                    Fields::SUM,
                    Fields::CURRENCY,
//                     Fields::SELLER_BANK_ACC,
//                     Fields::SELLER_NAME,
                    Fields::ORDER_REFERENCE,
                    Fields::DESCRIPTION,
                    Fields::SUCCESS_URL,
                    Fields::CANCEL_URL,
//                     Fields::USER_LANG,
                    Fields::VK_DATETIME
                );
            case Services::PAYMENT_SUCCESS:
                return array(
                    Fields::SERVICE_ID,
                    Fields::PROTOCOL_VERSION,
                    Fields::SELLER_ID,
                    Fields::SELLER_ID_RESPONSE,
                    Fields::ORDER_ID,
                    Fields::TRANSACTION_ID,
                    Fields::SUM,
                    Fields::CURRENCY,
                    Fields::SELLER_BANK_ACC_RESPONSE,
                    Fields::SELLER_NAME_RESPONSE,
                    Fields::SENDER_BANK_ACC,
                    Fields::SENDER_NAME,
                    Fields::ORDER_REFERENCE,
                    Fields::DESCRIPTION,
                    Fields::TRANSACTION_DATE,
                );
            case Services::PAYMENT_CANCEL:
                return array(
                    Fields::SERVICE_ID,
                    Fields::PROTOCOL_VERSION,
                    Fields::SELLER_ID,
                    Fields::SELLER_ID_RESPONSE,
                    Fields::ORDER_ID,
                    Fields::ORDER_REFERENCE,
                    Fields::DESCRIPTION,
                );
            case Services::AUTHENTICATE_REQUEST:
                return array(
                    Fields::SERVICE_ID,
                    Fields::PROTOCOL_VERSION,
                    Fields::SELLER_ID,
                    Fields::VK_REPLY,
                    Fields::SUCCESS_URL,
                    Fields::VK_DATETIME,
                    Fields::VK_RID,
                );
            case Services::AUTHENTICATE_SUCCESS:
                return array(
                    Fields::SERVICE_ID,
                    Fields::PROTOCOL_VERSION,
                    Fields::VK_USER,
                    Fields::VK_DATETIME,
                    Fields::SELLER_ID,
                    Fields::SELLER_ID_RESPONSE,
                    Fields::VK_USER_NAME,
                    Fields::VK_USER_ID,
                    Fields::VK_COUNTRY,
                    Fields::VK_OTHER,
                    Fields::VK_TOKEN,
                    Fields::VK_RID,              
                );
            default:
                throw new \InvalidArgumentException('Unsupported service id: '.$serviceId);
        }
    }

    /**
     * Fetch supported payment services
     *
     * @return array
     */
    public static function getPaymentServices()
    {
        return array(
            self::PAYMENT_REQUEST,
            self::PAYMENT_SUCCESS, 
            self::PAYMENT_CANCEL,
            self::PAYMENT_ERROR
        );
    }

    /**
     * Fetch supported authentication services
     *
     * @return array
     */
    public static function getAuthenticationServices()
    {
        return array(
            self::AUTHENTICATE_REQUEST,
            self::AUTHENTICATE_SUCCESS
        );
    }

    /**
     * Can't instantiate this class
     */
    private function __construct() {}
}