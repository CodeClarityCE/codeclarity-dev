# Web sign-ins live in HttpOnly cookies, and only Organization tokens are bearers

The web app and the API share one origin: Caddy serves the app at `https://<domain>/` and proxies `https://<domain>/api/*` to the API, in dev and in production. So the API itself sets both tokens of a sign-in as cookies, and no token is ever in a response body, in web storage or readable by JavaScript. RFC 10017 (OAuth 2.0 for Browser-Based Applications, BCP 212, August 2026) puts patterns that keep tokens out of the browser first (section 6: "presented in decreasing order of security"), and section 7.1 says an app whose frontend and API share a domain "can rely on server-side cookie-based session state" without OAuth. OWASP's Session Management Cheat Sheet says not to store "authentication tokens, session IDs, JWTs, refresh tokens, or any credential" in localStorage or sessionStorage. Before this, both tokens sat in localStorage, where any script on the page could read them and use them from elsewhere.

The tokens themselves do not change: a 15 minute access JWT (`typ: at+jwt`, `aud: codeclarity:access`) and an opaque refresh token that works once, rotated on every refresh with strict reuse detection (RFC 9700 sections 2.2.2 and 4.14.2). Only where they travel changes.

## The cookies

| Cookie                   | Holds             | Max-Age                        |
| ------------------------ | ----------------- | ------------------------------ |
| `__Host-Http-cc_access`  | the access JWT    | 15 minutes                     |
| `__Host-Http-cc_refresh` | the refresh token | until the sign-in's 7 days end |

Both are `HttpOnly; Secure; SameSite=Strict; Path=/` with no `Domain`, as RFC 10017 section 6.1.3.2 asks of a session cookie (Secure and HttpOnly MUST; SameSite=Strict, `Path=/`, no `Domain` and an HTTP-only name prefix SHOULD). The `__Host-Http-` prefix is the one that section names. A browser that knows it refuses the cookie unless it came from a response header with `HttpOnly`; one that does not still applies the `__Host-` rules, since prefixes match case-insensitively from the start of the name (RFC 6265bis-22 sections 4.1.3.2 and 5.4). Those rules stop a sibling subdomain from setting or shadowing the cookies.

The refresh cookie is not scoped to the refresh path. `__Host-` requires `Path=/`, RFC 6265bis section 4.1.2.4 says "the Path attribute cannot be relied upon for security", and the browser-visible path depends on the proxy prefix. A narrower `__Secure-` cookie would trade the protection against subdomain cookie injection for less exposure to our own same-origin servers, which already receive the access cookie.

Sign-in, refresh and password change answer with the two expiry times only. The app keeps those and a random id for the sign-in in localStorage, which hold no secret, so it knows when to refresh and other tabs can follow.

## Bearers and cookies are separate

A request with an `Authorization` header is judged on that header alone, and the only bearer the API accepts is an Organization token. A user access JWT sent as a bearer is refused, and the session cookies are ignored on such a request. A request without that header is a web sign-in, judged on the access cookie. So a pipeline cannot use a stolen web sign-in as a bearer, and a page cannot reach the API with a user's cookies by also sending a bearer.

## CSRF

RFC 10017 section 6.1.3.3 says a cookie-based backend "MUST implement a proper CSRF defense". Every request the API judges on a session cookie, including `POST /auth/refresh` and `POST /auth/sign_out`, any method, passes three checks, and each alone stops a cross-site request:

1. **SameSite=Strict**: the browser does not attach the cookies to a request a page on another site starts (RFC 10017 section 6.1.3.3.1, which calls it adequate only when no other app is same-site, hence the next two).
2. **A required custom header**, `X-CodeClarity-CSRF: 1` (RFC 10017 section 6.1.3.3.2: "the BFF MUST ensure that every incoming request carries this static header"; OWASP CSRF Prevention Cheat Sheet, "Employing Custom Request Headers for AJAX/API"). A cross-origin page can only send it after a CORS preflight, and the API answers no preflight, so it has no CORS configuration at all.
3. **Fetch Metadata, then Origin**: a `Sec-Fetch-Site` other than `same-origin` is refused; without that header, an `Origin` whose host is not the request's `Host` is refused (OWASP CSRF Prevention Cheat Sheet, "Fetch Metadata headers", which makes the Origin fallback "a mandatory requirement"). A client that sends neither header is not a browser, and the custom header is still required of it.

A refused request gets a 403 `CrossSiteRequestRefused`, so the app tells it apart from an expired sign-in.

## Considered Options

- **Status quo, tokens in localStorage**: any script on the page, through an XSS bug or a compromised dependency, can copy both tokens and keep using them from another machine for the rest of the 7 days. Rejected: it is what RFC 10017 section 6.3.4.2.1 and OWASP warn against.
- **Access token in memory, refresh token in an HttpOnly cookie** (the token-mediating backend of RFC 10017 section 6.2): no CSRF defense needed on ordinary calls, but the access token is still readable by any script on the page for up to 15 minutes, and each tab refreshes on load. Rejected: section 6.2 calls it "less secure than a BFF", and the maintainer asked for no token readable by JavaScript.
- **A backend-for-frontend with a server-side session id** (RFC 10017 section 6.1): the strongest pattern when an app calls third-party APIs, because tokens never leave the server. Here the API is the backend and is same-origin with the app, so cookies set by the API give the same property without a new service, a session store and a second hop. The access JWT in a cookie is CodeClarity's own credential, not a third-party token, so it is not encrypted (section 6.1.3.2 asks for that only when a cookie carries tokens to other APIs).

## Consequences

- RFC 10017 section 5.1.4 still applies: script running on the page can send requests through the user's browser while the page is open. Cookies stop the tokens from leaving the browser, not that. The content security policy and dependency hygiene remain the defense against XSS itself.
- Tools that sign in as a user (the fresh-install, results-gate and benchmark scripts, the api-fuzz `dev-account` profile) read the access token from the `Set-Cookie` header and send it back as `Cookie` with `X-CodeClarity-CSRF: 1`. Pipelines and the CLI keep using Organization tokens as bearers.
- The first load after the upgrade deletes the old localStorage entry, so each existing sign-in signs in once.
- The API and app release together: an app from before this change finds no tokens in the answer to sign-in, and an app from after it gets no cookies from an older API.
