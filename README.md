# SCVP API
An Open Source SCVP API for Bouncy Castle

The intent of this project is to build a minimum viable SCVP client using a recent BouncyCastle API in Java.

While this project uses the BouncyCastle Java API, it is primarily for ASN.1 processing of the objects used
within the protocol.  The example also uses the BouncyCastle API for the cryptographic operations, but is
being designed so that any cryptographic operation may be easily replaced using a different JCE provider.

I.e., another JCE provider that is, or makes use of, a FIPS 140 validated module.

Though, it is worth noting the BC API maintainers are working towards a FIPS validated module within the BC API:

https://www.bouncycastle.org/fips/BCFipsDescription-20140504.pdf
https://www.bouncycastle.org/fips/BCFipsDescription-20150101.pdf
https://www.bouncycastle.org/fips/BCFipsDescription-20150501.pdf

For SCVP, additional examples in other languages would be optimal...  I.e.:

JavaScript:  Using https://pkijs.org/
C/C++:  Using OpenSSL?  Revive PKIF?  http://pkif.sourceforge.net/
GO:  http://golang.org/pkg/crypto/x509/pkix/
Ruby:  http://ruby-doc.org/stdlib-1.9.3/libdoc/openssl/rdoc/OpenSSL.html

Why?  IMO, using "Trust Lists" for PKI enablement is becoming more complex, and thus less sustainable.  
If we have a method of centrally managing PKI based trust, and proper RFC 5280 path discovery and validation 
can be achieved with that implementation, then why are we not using it?

Let's face it, if the Server-Based Certificate Validation Protocol (SCVP) were implemented using JSON or XML 
messaging rather than ASN.1, there would likely be quite a few open source implementations, as well as
commercial implementations.  It's not a simple protocol, and frankly, there are not very many implementations.

Below are references to known commercial and open source client, server, and API implementations:

Commercial:

-Ascertia ADSS (http://www.ascertia.com/products/adss-scvp-server) [Server/Client/API]
-Axway (https://www.axway.com/en/enterprise-solutions/validation-authority) [Server/Client/API]
-Carillon (https://www.carillon.ca/en/pki-solutions/software-solutions.php) [Server/Client/API]
-HID/CoreStreet/Codebench (http://www.hidglobal.com/products/software/activid/activid-path-builder) [Server/Client/API]

Open Source:

-PKIF (http://pkif.sourceforge.net/) [Client/API] 
-UMU Java API (http://pki.inf.um.es/main.html?wload=/SCVP/index.html) [Client] <API not accessible to public>
-CADDISC (http://www-public.it-sudparis.eu/~lauren_m/CADDISC/Caddisc-eng.html) <Partial API using OpenSSL>
