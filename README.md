# Introduction
This library allows you to parse SAML metadata *fast* and extract some 
important data from it:

* ACS location, binding, index for SPs;
* SSO location, binding for IdPs;
* X.509 certificates used for signing and encryption by the IdP.

# API
To use this library, a simple API is available:

    $parser = new Parser("/path/to/metadata.xml");
    $data = $parser->getIdp("http://idp.example.org/");
    var_dump($data);
    
You will have access to the `keys`, `SingleSignOnService` keys in case of and
IdP. In case of an SP (`getSp("http://sp.example.org/")`) you will have access 
to the `AssertionConsumerService` key.
