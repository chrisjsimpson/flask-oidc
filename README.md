# OIDC walkthtough for ID Token validation based on RFCs

Taking the RFCs and walking through the steps involved
for [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
taking into account (and performing) the various validations the spec recommends
(such as CSRF,  Replay attack mitigations) and claim validations (such as `aud` -
audiance, `exp` - expiry etc).
