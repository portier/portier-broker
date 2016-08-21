Provisionary Portier protocol description
=========================================

This document attempts to describe the experimental Portier protocol as
implemented in the `portier-broker` daemon code (this repository) as well as
the Python `demo-rp` repository. Some of the acronyms used:

* RP: relying party, the site who would like to log the user in
* LA: an instance of the Portier broker
* IdP: the identity provider who will actually authenticate the user

In this concept approach, the RP delegates authentication to LA through an
OpenID Connect-like protocol. LA will in turn use one of three ways to
authenticate that the user owns the given email address:

* If the user's email domain supports "native" Portier authentication,
  this will be used. This has not been implemented; if we use OpenID Connect
  for this, that would be straightforward; however, it seems that OpenID
  Connect requires pre-registration of Portier (which acts as the RP relative
  to the IdP), which we would prefer not to require.
* Else, if the user uses one of the pre-configured "famous" IdPs, OpenID
  Connect is used to delegate authentication (with minimal transfer of
  knowledge, i.e. maximum privacy) to the IdP. This helps bootstrap the system.
* Else, the broker will send an email containing a short-lived one-time
  authentication pad to the user's email address. The code can be copied into
  a form in the original tab/window (not implemented in `ladaemon` right now),
  or the provided link can be clicked to resume logging in in a new tab/window.


A. RP -> Broker
---------------

1. **RP initiates login by submitting form (or XHR) to broker**

   ```
   POST /auth HTTP/1.1

   login_hint=me@example.com&
   scope=openid%20email&
   response_type=id_token&
   client_id=https://rp.info/&
   redirect_uri=https://rp.info/login
   ```

   * 200 OK -> wait for broker to request `redirect_uri` -> go to B3
   * 3xx -> IdP found, see B1 or B2
   * 4xx -> show some error message


B1. Broker -> IdP ("native" IdPs)
---------------------------------

Not currently implemented.


B2. Broker -> user (email loop)
-------------------------------

1. **Broker sends email to user with one-time authentication code**

   ```
   To: me@example.com
   From: Portier <broker@portier.io>
   Subject: Code: 328432 - Finish logging into https://rp.info

   Enter your login code:

   328432

   Or click this link:

   https://broker.portier.io/confirm?email=me@example.com&origin=https://rp.info&code=328432
   ```

2. **User enters code in current tab or clicks link from email** -> go to C


B2. Broker -> IdP ("famous" IdPs)
-----------------------------

1. **Broker requests OpenID configuration for authorization endpoint**

   ```
   GET /.well-known/openid-configuration HTTP/1.1

   200 OK

   {
     "authorization_endpoint": "https://famous.idp/auth",
   }
   ```

2. **Broker redirects RP request to famous IdP's authz endpoint**

   ```
   302 Found
   Location: {authorization_endpoint}?
             client_id=letsauth.famous.idp&
             response_type=code&
             scope=openid%20email&
             redirect_uri=https://broker.portier.io/callback&
             state=me@example.com:https://rp.info:<nonce>&
             login_hint=me@example.com
   ```

3. **Famous IdP returns user to broker's callback URL**

   ```
   GET /callback HTTP/1.1

   state=me@example.com:https://rp.info:<nonce>&
   code=8u3827587543
   ```

4. **Broker requests OpenID configuration for token endpoint and JWK document**

   ```
   GET /.well-known/openid-configuration HTTP/1.1

   200 OK

   {
     "token_endpoint": "https://famous.idp/tokens"
     "jwks_uri": "https://famous.idp/jwks"
   }
   ```

5. **Broker uses code from IdP to request id_token (JWT)**

   ```
   POST /tokens HTTP/1.1

   code=8u3827587543&
   client_id=portier.famous.idp&
   client_secret=<portier.famous.idp.secret>&
   redirect_uri=https://broker.portier.io/callback&
   grant_type=authorization_code

   200 OK

   {
     "id_token": "23i9424392u2.4328492439243.4324328432"
   }
   ```

6. **Broker requests keys from IdP to get public components of IdP's signing key**

   ```
   GET /jwks HTTP/1.1

   {
     "keys": [
       {
         "kid": "key-1",
         "n": "28294824239424",
         "e": "24293539258",
         "use": "sig"
       }
     ]
   }
   ```

7. **If `id_token` data checks out** -> go to C


C. Broker -> RP
---------------

1. **Broker posts JWT to RP callback URL**

   ```
   POST /login HTTP/1.1

   id_token=cY2339.832742474324723423423.3345854385358435438543543
   ```

TODO: how do we handle error paths?
