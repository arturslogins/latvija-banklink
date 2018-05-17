<?php

namespace Banklink\Protocol\Citadele;

final class Fields
{
    const XML_DATA = 'xmldata';
    const SERVICE_ID = 'request';
    const SERVICE_STATUS = 'code';

    const VK_USER = 'personalCode';
    const VK_INFO = 'person';

    /**
     * Can't instantiate this class
     */
    private function __construct() {}
}