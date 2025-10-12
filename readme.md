# mTLS To Headers

This Traefik plugin is essentially just a copy of the built-in PassTLSClientCert middleware, but outputs each certificate value into its own header (rather than all mashed together in X-Forwarded-Tls-Client-Info)
This repository includes an example plugin, `demo`, for you to use as a reference for developing your own plugins.

:warning: This is a pretty rough first pass on this, but it seems like something a handfull of people would get some good milage out of. I would *love* any PRs to improve / clean up this plugin.

## Usage

First, load the plugin in your static configuration

```yaml
#Static Configuration
experimental:
  plugins:
    example:
      moduleName: github.com/traefik/plugindemo
      version: v0.2.0
``` 

Then you can add it as middleware in your dynamic configuration
```yaml
#Dynamic Configuration
http:
  middlewares:
    mtls-to-headers:
      plugin:
        mtlsToHeaders:
          pem: Client-Cert
          info:
            sans:
              email: Email
            subject:
              commonname: CommonName
```

### Configuration

The general configuration structure (see example above) mirrors the [https://doc.traefik.io/traefik/reference/routing-configuration/http/middlewares/passtlsclientcert/](the PassTLSClientCert middleware) configuration with two key changes:
- Instead of a boolean for including each part of the certificate, you specify a string that will be appended to `X-Forwarded-Tls-` and set as a header value.
- The `sans` field is now broken down into `email`, `dns`, `ip`, and `uri`.

So for example, the configuration above would produce the following headers (with values from the presented certificate):
```
X-Forwarded-Tls-Client-Cert: <<CERTIFICATE>>
X-Forwarded-Tls-Commonname: me.example
X-Forwarded-Tls-Email: sam@example.com
```

### Need to Fix
- Unit tests don't really work yet
- Automated GitHub workflows don't quite work (partially because of tests)

### Future Changes
- Check for interest in a PR to update the built-in middleware with this functionality. Potentially could combine the configuration into somethingish like (with `infoHeader` to preserve the combined header if desired):
```yaml
http:
  middlewares:
    test-passtlsclientcert:
      passTLSClientCert:
        pem: "Client-Cert"
        info:
          notAfter: 
            infoHeader: true
            header: "Not-After"
```
- Potentially could add some certificate / CA validation in here, but that's probably better managed by Traefik's TLS stack or other plugins