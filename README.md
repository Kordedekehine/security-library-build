# full-spring-security

Stateless JWT security for a Spring Boot service in one annotation.

```java
@SpringBootApplication
@FullSpringSecurity(type = SecurityType.CLIENT)
public class BoilerplateApplication { }
```

That gives you a stateless filter chain that verifies RS256 bearer tokens
against a public key, derives authorities from a token claim, applies
per-endpoint role rules from configuration, and answers 401 and 403 as JSON.

The library **verifies** tokens. It never signs them — issuing is your auth
service's job.

> **Status: pre-1.0.** The `full-security.*` property names and the
> `UserAuthenticationProvider` SPI are stable in practice. The public API no
> longer exposes any JWT-library type, so upgrading jjwt underneath is not a
> breaking change for you. See [Limitations](#limitations) before adopting.

---

## Install

```xml
<dependency>
    <groupId>io.github.kordedekehine</groupId>
    <artifactId>full-spring-security</artifactId>
    <version>0.1.0-SNAPSHOT</version>
</dependency>
```

Requires Java 21 and Spring Boot 4.x.

---

## The one thing you must implement

`CLIENT` mode needs to turn a verified token subject into a local user. That
is the only code you write:

```java
@Service
public class LoadUser implements UserAuthenticationProvider {

    @Override
    public UserDetails loadUser(String username) {
        return User.withUsername(username)
                .password("")
                .authorities(List.of())
                .build();
    }
}
```

Return identity and account state. **Do not put roles here** — authorities
come from the token, because the issuer is the source of truth for what a
caller may do. Anything you return from `loadUser` is used only when the
token carries no role claim at all.

The account flags are enforced: a principal that is disabled, locked, or
expired is rejected with 401 even when its token verifies.

If no `UserAuthenticationProvider` bean exists, the context fails at startup
with a message naming the interface — it does not silently start unsecured.

---

## Minimum configuration

```properties
full-security.client.public-key=${JWT_PUBLIC_KEY}
full-security.public-endpoints=/public/**
```

In deployed environments set `FULL_SECURITY_CLIENT_PUBLIC_KEY` instead of a
placeholder — Spring's relaxed binding maps it onto the property directly.

---

## Where verification keys come from

Two sources. `jwks-uri` wins when both are set.

### A JWKS endpoint — preferred

```properties
full-security.client.jwks-uri=https://auth-service/.well-known/jwks.json
```

Keys are selected by the token's `kid` header, so **rotation is picked up
without a redeploy**. The set is cached (`jwks-cache-ttl`, default 15m); an
unknown `kid` triggers one refresh, rate limited by `jwks-refresh-cooldown`
so junk kids can't be used to hammer your issuer through this service. If a
refresh fails, the cached set keeps serving rather than taking every request
down.

Tokens must carry a `kid` header for this to work — without one there is
nothing to select on, and the request is rejected.

### A static public key

```properties
full-security.client.public-key=${JWT_PUBLIC_KEY}
```

Base64 of an X.509 public key:

```bash
openssl rsa -in private.pem -pubout -outform DER | base64 | tr -d '\n'
```

**RSA, EC and EdDSA are all supported** — the algorithm is read from the key
itself, not assumed. PEM armour and newlines are stripped, so a key pasted
straight out of a `.pem` file works. Set `key-algorithm` only to skip
detection.

## What a token must contain

```json
{
  "sub": "taiwo",
  "role": "ADMIN",
  "iss": "auth-service",
  "aud": "orders-service",
  "exp": 1788331957
}
```

| Claim | Required | Notes |
|---|---|---|
| `sub` | yes | Becomes the username passed to `loadUser`. Blank subject → 401. |
| `exp` | yes | Checked with `clock-skew-seconds` tolerance. |
| role claim | no | Name it with `role-claim`. String or array. Absent → falls back to `loadUser` authorities. |
| `iss` | only if `issuer` is set | Mismatch → 401. |
| `aud` | only if `audience` is set | Mismatch → 401. |

A role of `ADMIN` becomes authority `ROLE_ADMIN`. Write `ADMIN` or
`ROLE_ADMIN` in config — both work, the prefix is normalised.

---

## Authorization rules

Ordered, first match wins. Put the most specific pattern first.

```properties
full-security.rules[0].pattern=/api/v1/admin/**
full-security.rules[0].roles=ADMIN

full-security.rules[1].pattern=/api/v1/data/**
full-security.rules[1].methods=DELETE
full-security.rules[1].roles=ADMIN

full-security.rules[2].pattern=/api/v1/data/**
full-security.rules[2].methods=GET
full-security.rules[2].roles=USER,ADMIN

full-security.rules[3].pattern=/api/v1/health-check
full-security.rules[3].authenticated=true
```

Each rule picks **exactly one** outcome — `roles`, `authenticated=true`, or
`permit-all=true`. Picking none or several fails the context at startup with
a message naming the pattern, rather than leaving an endpoint open.

`methods` is optional; omit it to cover every verb.

### Evaluation order

Matchers are registered in this order, and the first match wins:

1. Container dispatches (`ERROR`, `FORWARD`, `ASYNC`) — always permitted
2. `public-endpoints`
3. Swagger paths, when enabled
4. `actuator.public-endpoints`
5. Everything else under `/actuator/**`, when `actuator.roles` is set
6. `rules`, in the order you declare them
7. `anyRequest().authenticated()`

Because public endpoints are registered before rules, a path matched by
`public-endpoints` cannot be re-restricted by a later rule. Order accordingly.

---

## Docs and observability

```properties
full-security.swagger.enabled=true
full-security.actuator.public-endpoints=health,info
full-security.actuator.roles=ADMIN
```

`swagger.enabled` opens the springdoc surfaces — `/swagger-ui/**`,
`/v3/api-docs/**`, `/swagger-resources/**`, `/webjars/**`. Override the list
with `full-security.swagger.paths` if your setup differs.

Actuator is handled in two halves: the ids in `public-endpoints` are open, and
everything else under `/actuator/**` requires `actuator.roles`. Leave both
empty and actuator falls through to `anyRequest().authenticated()`.

These only add matchers. They do not add springdoc or actuator to your
classpath — without those dependencies the paths simply 404.

**Zipkin needs no rule.** Tracing is outbound: your app pushes spans to a
Zipkin collector. There is no inbound endpoint to protect unless you host the
Zipkin UI in the same app, in which case treat it as a normal rule.

---

## Method-level security

`@EnableMethodSecurity` is on, so annotations work with no extra setup:

```java
@GetMapping("/reports")
@PreAuthorize("hasRole('ADMIN')")
public String reports() { ... }
```

Use `rules` for coarse path policy and `@PreAuthorize` for anything needing
argument or ownership checks. Both are enforced; the path rule runs first.

---

## Service-to-service calls

`SERVICE` mode is for machine callers. They present a shared key in a header
rather than a user token:

```properties
full-security.service.header=X-API-Key

full-security.service.callers[0].id=orders-service
full-security.service.callers[0].key=${ORDERS_SERVICE_KEY}
full-security.service.callers[0].roles=SERVICE,ORDERS

full-security.service.callers[1].id=billing-service
full-security.service.callers[1].key=${BILLING_SERVICE_KEY}
full-security.service.callers[1].roles=SERVICE
```

```java
@SpringBootApplication
@FullSpringSecurity(type = SecurityType.SERVICE)
public class ReportingApplication { }
```

The caller's `id` becomes the authenticated principal, so `Authentication
.getName()` tells you which service called, and its roles work with the same
`rules` and `@PreAuthorize` as anything else.

Keys are compared with a constant-time check, and every configured credential
is checked rather than stopping at the first match, so response timing does
not reveal a valid key. A request with no key header passes through untouched
so public endpoints stay reachable. A caller configured without a key fails
the context at startup, naming the caller.

**Supply keys from the environment**, never a committed file. They are shared
secrets: anyone holding one can impersonate that service.

Which mode do you want?

| | `CLIENT` | `SERVICE` |
|---|---|---|
| Credential | JWT bearer token | Shared key header |
| Identity from | Token `sub` + your `loadUser` | Configured caller `id` |
| Roles from | Token role claim | Configured caller roles |
| Key rotation | JWKS, no redeploy | Redeploy with new secret |
| Use for | End users, and machines that already hold a JWT | Internal calls between your own services |

---

## Error responses

| Situation | Status |
|---|---|
| No token on a protected route | 401 |
| Malformed, expired, or wrong-key token | 401 |
| Wrong issuer or audience | 401 |
| Disabled, locked, or expired account | 401 |
| Valid token, insufficient role | 403 |

```json
{
  "status": 401,
  "error": "Unauthorized",
  "message": "Authentication required. Supply a valid Bearer token.",
  "path": "/api/v1/admin/reports"
}
```

401 responses carry `WWW-Authenticate: Bearer`. Messages are fixed strings —
no token or request content is reflected back to the caller.

A request with no `Authorization` header is passed down the chain rather than
rejected outright, so public endpoints stay reachable and Spring decides.

---

## CORS

```properties
full-security.cors.enabled=true
full-security.cors.allowed-origins=https://app.example.com
full-security.cors.allow-credentials=true
```

Origins are applied as **patterns**, so a wildcard works alongside
`allow-credentials` — which plain allowed-origins forbids. Disabled by
default.

---

## Full property reference

| Property | Default | Meaning |
|---|---|---|
| `full-security.public-endpoints` | empty | Ant patterns open to everyone |
| `full-security.client.jwks-uri` | none | JWKS endpoint. Takes precedence over `public-key` |
| `full-security.client.jwks-cache-ttl` | `15m` | How long a fetched key set is trusted |
| `full-security.client.jwks-refresh-cooldown` | `30s` | Floor between refreshes on unknown `kid` |
| `full-security.client.jwks-timeout` | `5s` | Connect timeout for the JWKS endpoint |
| `full-security.client.public-key` | — | Base64 X.509 public key: RSA, EC or EdDSA |
| `full-security.client.key-algorithm` | detected | Skip detection: `RSA`, `EC`, `EdDSA` |
| `full-security.client.issuer` | none | When set, `iss` must match |
| `full-security.client.audience` | none | When set, `aud` must match |
| `full-security.client.role-claim` | `role` | Claim carrying the caller's roles |
| `full-security.client.clock-skew-seconds` | `60` | Expiry tolerance |
| `full-security.rules[n].pattern` | — | Ant pattern. Required |
| `full-security.rules[n].roles` | empty | Any-of role list |
| `full-security.rules[n].methods` | empty | Limit to these verbs |
| `full-security.rules[n].permit-all` | `false` | Open the pattern |
| `full-security.rules[n].authenticated` | `false` | Any valid token |
| `full-security.swagger.enabled` | `false` | Open springdoc paths |
| `full-security.swagger.paths` | springdoc set | Override the path list |
| `full-security.actuator.public-endpoints` | empty | Open actuator ids |
| `full-security.actuator.roles` | empty | Roles for the rest of `/actuator/**` |
| `full-security.cors.*` | disabled | See CORS above |
| `full-security.service.header` | `X-API-Key` | Header carrying the caller's key |
| `full-security.service.callers[n].id` | — | Calling service name; becomes the principal |
| `full-security.service.callers[n].key` | — | Shared secret. Supply from the environment |
| `full-security.service.callers[n].roles` | empty | Roles granted to that caller |

Every optional surface defaults closed. Opting in is always explicit.

---

## Common cases

**Public API with an authenticated admin area**

```properties
full-security.public-endpoints=/api/v1/catalog/**
full-security.rules[0].pattern=/api/v1/admin/**
full-security.rules[0].roles=ADMIN
```

**Read open, writes restricted**

```properties
full-security.rules[0].pattern=/api/v1/orders/**
full-security.rules[0].methods=GET
full-security.rules[0].authenticated=true

full-security.rules[1].pattern=/api/v1/orders/**
full-security.rules[1].methods=POST,PUT,PATCH,DELETE
full-security.rules[1].roles=OPERATOR,ADMIN
```

**Several services, one signing key** — set `audience` per service so a token
minted for one is rejected by the others.

**Roles under a non-standard claim** — Keycloak-style nesting is not yet
supported; `role-claim` reads a top-level claim only. Flatten it at issue time
or map it in your auth service.

---

## Troubleshooting

**Everything returns 401, even paths that should be public.** Your public
pattern probably doesn't match. Patterns are Ant-style and absolute:
`/public/**`, not `public/**`.

**A 404 comes back as 401.** Fixed — container dispatches are permitted. If
you see this, you are on a build older than the error-dispatch fix.

**`full-security.client.public-key is not set`.** The property is missing or
empty. The app fails fast on the first token rather than at startup, because
the key is only read when a token arrives.

**Valid token, but 403 everywhere.** The role claim name probably doesn't
match `role-claim`. The token authenticates — `sub` is fine — but carries no
authorities. Decode the payload and compare the claim name.

**`ROLE_ROLE_ADMIN` in a log.** Harmless; the prefix is normalised. Write
either spelling.

---

## Limitations

Know these before adopting:

- **Pre-1.0.** The API may still change before 1.0.
- **The role claim must be top-level.** Keycloak-style nesting
  (`realm_access.roles`) is not read — flatten it at issue time.
- **HMAC / shared-secret JWTs are not supported**, deliberately: with a
  symmetric key every verifying service can also mint tokens. Use asymmetric
  keys for user tokens, and the service-key mechanism above for machines.
- **One issuer and one audience** per service. Multiple accepted issuers are
  not supported.
- **JWKS is fetched over plain HTTP if you configure an `http://` URL.** Use
  `https` anywhere real.

## Building

```bash
./mvnw clean install
```
