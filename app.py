from flask import Flask, redirect, request, url_for, session
import requests
from uuid import uuid4
from operator import itemgetter
import json
import base64
import hashlib
import time

"""
Guided learning session
https://gemini.google.com/app/71be15fb7682dec5
"""

openid_discovery_endpoint = (
    "http://127.0.0.1:8080/realms/karmacomputing/.well-known/openid-configuration"
)

trusted_issuer = "http://127.0.0.1:8080/realms/karmacomputing"
authorization_endpoint = (
    "http://127.0.0.1:8080/realms/karmacomputing/protocol/openid-connect/auth"
)

token_endpoint = (
    "http://127.0.0.1:8080/realms/karmacomputing/protocol/openid-connect/token"
)

client_id = "flask-oidc"

app = Flask(__name__)
app.config["SECRET_KEY"] = str(uuid4())


def get_redirect_uri():
    return url_for("process_authentication_response", _external=True)


@app.route("/")
def hello_world():
    return "<p>Hello, World!</p><a href='/login'>Login</a>"


@app.route("/login")
def login():
    # Generate a state value for the request to protect against CSRF
    # See:
    # https://openid.net/specs/openid-connect-core-1_0.html#ImplicitTokenValidation:~:text=a%20native%20application.-,state,-RECOMMENDED.%20Opaque%20value
    state = str(uuid4())
    # Note that we don't *actually* have a "user-agent's authenticated state"
    # to create such a value at this point, so the creation here, as recomended
    # https://www.rfc-editor.org/rfc/rfc6749.html#section-10.12 is a bit mute
    # at this stage given the app is open access (anybody can generate a valid
    # state value- best case this means requests at least *originated* by this
    # app (so yes, CSRF mitigation is achieved, at least).
    # Note sending the state value to the authorization endpoint is
    # "RECOMMENDED" not "MUST" in OIDC:
    # https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
    session["OIDC_CSRF_state"] = state

    # Compute a nonce and tie it to the users session
    # in support of ID Token validation 11.:
    # "If a nonce value was sent in the Authentication Request, a nonce
    # Claim MUST be present and its value checked to verify that it is
    # the same value as the one that was sent in the Authentication Request.
    # The Client SHOULD check the nonce value for replay attacks. The precise
    # method for detecting replay attacks is Client specific.
    # Recall that the nonce value is only sent back in the ID Token from
    # the identify provider- it's not sent back in it's first response (the
    # redirect) like the state value is (which we store as OIDC_CSRF_state)
    # The state parameter provides protection against CSRF attacks,
    # whereas the nonce value mitigates replay attacks (which is why it's
    # value it *not* sent back in the return url, but *is* present in
    # the token response, so the app (client) can skip and say 'woopise'
    # you cannot re-use that token, abort/reject. (TODO remember to clear/
    # reset the nonce value after each succesful usage within session).
    nonce = str(uuid4())
    session["nonce"] = nonce

    url = f"{authorization_endpoint}?response_type=code&scope=openid%20profile%20email&client_id={client_id}&redirect_uri={get_redirect_uri()}&state={state}&nonce={nonce}"
    return redirect(url)


# https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth:~:text=%C2%A0TOC-,3.1.2.5.%C2%A0%20Successful%20Authentication%20Response,-An%20Authentication%20Response
@app.route("/authentication-response")
def process_authentication_response():
    print(request)
    # Get code needed to send to token endpoint so that
    # we can get an Access Token, ID Token, and optionally a
    # refresh token.
    code = request.args.get("code")

    # The OAuth 2.0 Authorization Framework RFC 6749
    # 10.12.  Cross-Site Request Forgery
    # The client MUST implement CSRF protection for its redirection URI.
    # This is typically accomplished by requiring any request sent to the
    # redirection URI endpoint to include a value that binds the request to
    # the user-agent's authenticated state (e.g., a hash of the session
    # cookie used to authenticate the user-agent).  The client SHOULD
    # utilize the "state" request parameter to deliver this value to the
    # authorization server when making an authorization request.
    # https://www.rfc-editor.org/rfc/rfc6749.html#section-10.12
    state = request.args.get("state")
    # Validate state matches the state value we geenrated prior to
    # contacting the authorisation server
    assert state == session.get("OIDC_CSRF_state")

    # Post code to the token endpoint
    # https://www.rfc-editor.org/rfc/rfc6749.html#section-3.2
    # & inspect the authorisation server response
    # https://www.rfc-editor.org/rfc/rfc6749.html#section-4.1.2
    # Where `code` and `state` are required
    # to be present in its response
    resp = requests.post(
        token_endpoint,
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": get_redirect_uri(),
            "client_id": client_id,
        },
    )
    data = resp.json()

    # 3.1.2.7.  Authentication Response Validation
    # When using the Authorization Code Flow, the Client MUST
    # validate the response according to RFC 6749, especially
    # Sections 4.1.2 and 10.12.
    # https://www.rfc-editor.org/rfc/rfc6749.html#section-10.12:~:text=4.1.2.%20%20Authorization%20Response

    message = (
        f"--- Token Endpoint Response ---\n"
        f"Keys Received: {list(data.keys())}\n\n"
        f"Access Token:       {data.get('access_token')}\n"
        f"ID Token:           {data.get('id_token')}\n"
        f"Refresh Token:      {data.get('refresh_token')}\n"
        f"Token Type:         {data.get('token_type')}\n"
        f"Expires In:         {data.get('expires_in')}s\n"
        f"Refresh Expires In: {data.get('refresh_expires_in')}s\n"
        f"Not Before Policy:  {data.get('not-before-policy')}\n"
        f"Session State:      {data.get('session_state')}\n"
        f"Scope:              {data.get('scope')}\n"
        f"-------------------------------"
    )
    print(message)

    # Decode & validate the token (JSON Web Signature (JWS)
    # The value of the id_token parameter is the ID Token, which is a signed
    # JWT, containing three base64url-encoded segments separated by period ('.')
    # characters. The first segment represents the JOSE Header. Base64url
    # decoding it will result in the following set of Header Parameters
    # https://openid.net/specs/openid-connect-core-1_0.html#AuthorizationExamples:~:text=The%20value%20of%20the%20id_token
    #
    # Recall that in JWS, Base64url Encoding is used "with all trailing '='
    #  characters omitted (as permitted by Section 3.2) and without the
    #  inclusion of any line breaks, whitespace, or other additional
    #  characters."
    # Therefore, in order to decode using python, that padding needs to be
    # recalculated (by modulas 4, and added back to the strings as/if needed)

    # Decode the `id_token` JOSE Header (part 1)
    # https://openid.net/specs/openid-connect-core-1_0.html#IDToken:~:text=The%20first%20segment%20represents%20the%20JOSE%20Header
    # id_token definition:
    # https://openid.net/specs/openid-connect-core-1_0.html#IDToken
    # Deep diver https://bugs.python.org/issue29427
    # The structure of the 'parts' of a JWT are well explained
    # with an example in the RFC 7519 section 3.1:
    # https://datatracker.ietf.org/doc/html/rfc7519#section-3.1
    # with the third part (JWT signature, called a JWS) is defined in
    # RFC 7515 https://www.rfc-editor.org/rfc/rfc7515.html

    part1 = data.get("id_token").split(".")[0]
    JOSE_header = json.loads(base64.urlsafe_b64decode(f"{part1}==="))
    alg, typ, kid = itemgetter("alg", "typ", "kid")(JOSE_header)

    # Now let's extract the claims from the JTW
    # (Note we have *not* validates the claims yet, only
    # recieved them. You wouldn't just take them on face value now, would you?)
    # Note: The registered Claim Names (such as `iss` and `sub`) & values are
    # defined in:
    # https://datatracker.ietf.org/doc/html/rfc7519#section-4.1
    part2 = data.get("id_token").split(".")[1]
    claims_unvalidated = json.loads(base64.urlsafe_b64decode(f"{part2}==="))

    # signing_input (this is what we're about to be validating)
    # Its value (taken directly from the RFC is built up by:
    # ASCII(BASE64URL(UTF8(JWS Protected Header)) || '.' || BASE64URL(JWS Payload)).
    # See: https://www.rfc-editor.org/rfc/rfc7515.html#section-3.1:~:text=encoding%20without%20padding.)-,JWS%20Signing%20Input,-The%20input%20to
    # Se we do:
    signing_input = f"{part1}.{part2}".encode("ascii")

    # Not let's unpack and validate the JWS Signature (part3)
    part3 = data.get("id_token").split(".")[2]

    signature_int = int.from_bytes(base64.urlsafe_b64decode(f"{part3}==="))

    # Get the public keys from the jwks url, and extract the modulus `n`
    # and exponent `e` for the `kid` from the JOSE_header
    jwks_key_info = requests.get(
        "http://127.0.0.1:8080/realms/karmacomputing/protocol/openid-connect/certs"
    ).json()["keys"][
        1
    ]  # TODO filter on kid
    assert jwks_key_info["kid"] == JOSE_header["kid"]
    # The eponent will be 65537
    # Why?
    # See https://en.wikipedia.org/wiki/65,537
    eponent_e_decoded = int.from_bytes(
        base64.urlsafe_b64decode(f"{jwks_key_info['e']}==="), byteorder="big"
    )
    modulus_n_decoded = int.from_bytes(
        base64.urlsafe_b64decode(f"{jwks_key_info['n']}==="), byteorder="big"
    )

    # Do the RSA dance where
    # m holds the decrypted mathematical integer
    m = pow(signature_int, eponent_e_decoded, modulus_n_decoded)
    # For RSA the length of the decrypted singature is always equal to the size
    # of the public key's modulus (which we stored in modulus_n_decoded)
    key_size_bytes = (modulus_n_decoded.bit_length() + 7) // 8
    decrypted_bytes = m.to_bytes(key_size_bytes, byteorder="big")

    # Getting ready to compare our calculated hash with the one we recieved:
    # Remember signing_input we assembled by concatenating part1 (JOSE_header)
    # and part2 (the claims) and encoding them to ascii.
    our_hash = hashlib.sha256(signing_input).digest()

    # Verify that our computed hash matched the recieved hash
    # Recall that we have taken the origionally recieved part3 of
    # the message into signature_int, and separately, generated our own hash
    # (our_has) to compare it.
    # This is to fulfill the spec 3.1.3.7. 'ID Token Validation'
    # and is going beyond what the spec needed given we *do* have direct
    # communication between the client and the Token Endpoint (but it's
    # not TLS in this demo). The spec says:
    # "6. If the ID Token is received via direct communication between
    # the Client and the Token Endpoint (which it is in this flow), the
    # TLS server validation MAY be used to validate the issuer in place of
    # checking the token signature. The Client MUST validate the signature of
    # all other ID Tokens according to JWS [JWS] using the algorithm specified
    # in the JWT alg Header Parameter. The Client MUST use the keys provided by
    # the Issuer
    assert our_hash == decrypted_bytes[-32:]

    # Since we've now validated the signature cryptographically
    # We can now verify the claims are still valid, such as exp (expiry)
    assert claims_unvalidated.get("exp") > time.time()

    # Under the OIDC spec, we also need to verify the ID Token Validation
    # claims:
    # https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation

    # "2. The Issuer Identifier for the OpenID Provider (which is typically
    # obtained during Discovery) MUST exactly match the value of the
    # iss (issuer) Claim"
    assert trusted_issuer == claims_unvalidated.get("iss")

    # "3. The Client MUST validate that the aud (audience) Claim contains its
    # client_id value registered at the Issuer identified by the iss (issuer) Claim as
    # an audience. The aud (audience) Claim MAY contain an array with more than one
    # element. The ID Token MUST be rejected if the ID Token does not list the Client
    # as a valid audience, or if it contains additional audiences not trusted by the
    # Client."
    assert client_id == claims_unvalidated.get("aud")

    # 4. and 5. 'azp' are out of scope ("If the implementation is using extensions")

    # "11. If a nonce value was sent in the Authentication Request, a nonce Claim MUST
    # be present and its value checked to verify that it is the same value as the one
    # that was sent in the Authentication Request. The Client SHOULD check the nonce
    # value for replay attacks. The precise method for detecting replay attacks is
    # Client specific."
    assert session.get("nonce") == claims_unvalidated.get("nonce")
    breakpoint()
    return f"<pre>{message}</pre>"
