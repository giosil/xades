# XAdES

Utility .net class to sign xml width XAdES-BES (XML Advanced Electronic Signatures) digital signature.

## Example

```csharp
String sXml = "<x></x>";

XAdES xades = new XAdES("CERTNAME");

String sOut = xades.Sign(sXml, true);
```

## Contributors

* [Giorgio Silvestris](https://github.com/giosil)
