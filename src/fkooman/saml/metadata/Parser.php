<?php

namespace fkooman\saml\metadata;

use fkooman\X509\CertParser;

class Parser
{
    /** @var array */
    private $md;

    public function __construct($metadataFile)
    {
        $this->md = @simplexml_load_file($metadataFile);
        if (false === $this->md) {
            throw new ParserException("unable to read metadata file");
        }
        $this->md->registerXPathNamespace('md', 'urn:oasis:names:tc:SAML:2.0:metadata');
    }

    public function getIdp($entityId)
    {
        $md = array(
            "SingleSignOnService" => array(),
            "keys" => array()
        );

        $result = $this->md->xpath('//md:EntityDescriptor[@entityID="' . $entityId . '"]/md:IDPSSODescriptor/md:SingleSignOnService');

        if (0 === count($result)) {
            // no SingleSignOnService entry for this entityID in metadata
            throw new ParserException("entity not found in metadata, or no SingleSignOnService");
        }

        foreach ($result as $ep) {
            array_push($md['SingleSignOnService'], array("Binding" => (string) $ep['Binding'], "Location" => (string) $ep['Location']));
        }

        $result = $this->md->xpath('//md:EntityDescriptor[@entityID="' . $entityId . '"]/md:IDPSSODescriptor/md:KeyDescriptor');
        if (0 === count($result)) {
            // no KeyDescriptor entry for this entityID in metadata
            throw new ParserException("entity not found in metadata, or no KeyDescriptor");
        }

        foreach ($result as $cd) {
            $key = array(
                "type" => "X509Certificate",
                "X509Certificate" => null,
                "encryption" => false,
                "signing" => false
            );

            if (!isset($cd['use'])) {
                $key['encryption'] = true;
                $key['signing'] = true;
            } else {
                $use = (string) $cd['use'];
                $key[$use] = true;
            }

            $certData = new CertParser((string) $cd->children("http://www.w3.org/2000/09/xmldsig#")->KeyInfo->X509Data->X509Certificate);
            $key['X509Certificate'] = $certData->toBase64();

            array_push($md['keys'], $key);
        }

        return $md;
    }

    public function getSp($entityId)
    {
        $md = array(
            "AssertionConsumerService" => array()
        );

        $result = $this->md->xpath('//md:EntityDescriptor[@entityID="' . $entityId . '"]/md:SPSSODescriptor/md:AssertionConsumerService');
        if (0 === count($result)) {
            // no AssertionConsumerService entry for this entityID in metadata
            throw new ParserException("entity not found in metadata, or no AssertionConsumerService");
        }

        foreach ($result as $ep) {
            array_push($md['AssertionConsumerService'], array("Binding" => (string) $ep['Binding'], "Location" => (string) $ep['Location'], "index" => (int) $ep['index']));
        }

        return $md;
    }
}
