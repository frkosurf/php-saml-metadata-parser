<?php

require_once 'vendor/autoload.php';

use fkooman\saml\metadata\Parser;

class ParserTest extends PHPUnit_Framework_TestCase
{
    public function testIdp()
    {
        $p = new Parser("tests/data/surfconext-idp.xml");
        $data = $p->getIdp("https://engine.surfconext.nl/authentication/idp/metadata");
        $this->assertEquals("MIIDyzCCArOgAwIBAgIJAMzixtXMUH1NMA0GCSqGSIb3DQEBBQUAMHwxCzAJBgNVBAYTAk5MMRAwDgYDVQQIDAdVdHJlY2h0MRAwDgYDVQQHDAdVdHJlY2h0MRUwEwYDVQQKDAxTVVJGbmV0IEIuVi4xEzARBgNVBAsMClNVUkZjb25leHQxHTAbBgNVBAMMFGVuZ2luZS5zdXJmY29uZXh0Lm5sMB4XDTExMDEyNDEwMTg1N1oXDTIxMDEyMzEwMTg1N1owfDELMAkGA1UEBhMCTkwxEDAOBgNVBAgMB1V0cmVjaHQxEDAOBgNVBAcMB1V0cmVjaHQxFTATBgNVBAoMDFNVUkZuZXQgQi5WLjETMBEGA1UECwwKU1VSRmNvbmV4dDEdMBsGA1UEAwwUZW5naW5lLnN1cmZjb25leHQubmwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDMJ6v+f3owS3KR5IXSil+3XFwGvCVeYx3jDOFKAnwvXlDpTu+t730b8/spHtlopyJVAlb6qBIPN7R4TGTLqiu0zebYsYx/PtqCk5cbu9qs3h+p2BBoTXVwXA/ZYi0tqtxp04hcNrRj1TAgLyC0S+KASTF+zzccAcjTBid5EMioo+YllgSEobWJ4X33XVRqNrikAPDsNmDrdKUi257JSO2xhVIG5lbtmDaL5ORCD56oRmVdp7VQTEQ3Yass8J5Rn+Ub6WmRBYeG+KzFBvtyBput2o0/gvtJn9L+NWeDB0LyUPaUYG/X4GF14FcmFQfz7I5jBCNHtPcLJbPYbZKQNhz/AgMBAAGjUDBOMB0GA1UdDgQWBBS9QqP8gtMM6nm4oYzNbgqhEDP1aDAfBgNVHSMEGDAWgBS9QqP8gtMM6nm4oYzNbgqhEDP1aDAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBBQUAA4IBAQBH2qyYwLwesIOxUTj+NJ0VXRBDH8VecNLiUUs9Np4x8A0pxLvlNnv5TdJAruEg1LSVmAqqPUdAB2m7CKDeUVM9cwOB7vqelV2GNgOfevXi+DZRMffyyE8qyIcnTqvDOgcR8qGTPSVT+SIsOkV9bYrjltrbnal7cJermsA8SC5w/pjLaOHI1xIZHquZzymWoN3Zfz2CQg2r5o+AURYd74GrHhHqVa9VrdWtcimB+vTQQihoLt8YciehpJjOMpx2D66eFfpC8ix31RRdjAVIo1y33h1yU3gEHePDbOthZE+lpXi2WJqO85H85LqJOtgn2WPI3P2Tx32Cq1WXCYkxLaPI", $data['keys'][0]['X509Certificate']);
        $this->assertTrue($data['keys'][0]['signing']);
        $this->assertFalse($data['keys'][0]['encryption']);
        $this->assertEquals("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", $data['SingleSignOnService'][0]['Binding']);
        $this->assertEquals("https://engine.surfconext.nl/authentication/idp/single-sign-on", $data['SingleSignOnService'][0]['Location']);
    }

    public function testSp()
    {
        $p = new Parser("tests/data/surfconext-sp.xml");
        $data = $p->getSp("https://engine.surfconext.nl/authentication/sp/metadata");
        $this->assertEquals("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", $data['AssertionConsumerService'][0]['Binding']);
        $this->assertEquals("https://engine.surfconext.nl/authentication/sp/consume-assertion", $data['AssertionConsumerService'][0]['Location']);
        $this->assertEquals(0, $data['AssertionConsumerService'][0]['index']);
    }
}
