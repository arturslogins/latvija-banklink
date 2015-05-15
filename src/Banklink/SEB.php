<?php

namespace Banklink;

use Banklink\Protocol\iPizza;

/**
 * Banklink implementation for SEB bank using iPizza protocol for communication
 * For specs see http://seb.ee/en/business/collection-payments/collection-payments-web/bank-link-specification
 *
 * @author Roman Marintsenko <inoryy@gmail.com>
 * @since  11.01.2012
 */
class SEB extends Banklink
{
    protected $requestUrl = 'https://www.seb.ee/cgi-bin/unet3.sh/un3min.r';
    protected $testRequestUrl = 'https://www.seb.ee/cgi-bin/dv.sh/un3min.r';
//     protected $testRequestUrl = 'https://pangalink.net/banklink/seb-common';


    /**
     * Force iPizza protocol
     *
     * @param \Banklink\Protocol\iPizza $protocol
     * @param boolean                   $testMode
     * @param string | null             $requestUrl
     */
    public function __construct($protocol, $testMode = false, $requestUrl = null)
    {
        parent::__construct($protocol, $testMode, $requestUrl);
    }

    /**
     * @inheritDoc
     */
    protected function getEncodingField()
    {
        return 'VK_ENCODING';
    }

    /**
     * Force UTF-8 encoding
     *
     * @see Banklink::getAdditionalFields()
     *
     * @return array
     */
    protected function getAdditionalFields()
    {
        return array(
            'VK_ENCODING' => $this->requestEncoding
        );
    }
}