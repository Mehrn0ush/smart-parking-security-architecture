# Attack Paths Modeled In `workspace.dsl`

## Explicitly Modeled External Attack Paths

The DSL models these direct attack relationships:

1. `External Attacker -> API Gateway` using `HTTPS`
2. `External Attacker -> Gateway Service` using `MQTT`
3. `Script Kiddie -> ANPR Service` using `HTTPS`
4. `Nation State Actor -> Edge AI Runtime` using `HTTPS`

References:

- [`workspace.dsl:620`](../model/workspace.dsl#L620)
- [`workspace.dsl:623`](../model/workspace.dsl#L623)
- [`workspace.dsl:626`](../model/workspace.dsl#L626)
- [`workspace.dsl:629`](../model/workspace.dsl#L629)

## Explicitly Modeled Internal Attack Paths

The DSL models these insider relationships:

1. `Malicious Insider -> Identity Provider`
2. `Malicious Insider -> Secrets Manager`
3. `Malicious Insider -> Data Lake`

References:

- [`workspace.dsl:634`](../model/workspace.dsl#L634)
- [`workspace.dsl:637`](../model/workspace.dsl#L637)
- [`workspace.dsl:640`](../model/workspace.dsl#L640)

## Security Meaning Of These Paths

### `External Attacker -> API Gateway`

This is the standard public attack surface. The model treats it as high risk, which is appropriate because it fronts mobile, admin, ANPR, access control, parking, and payment routes.

### `External Attacker -> Gateway Service`

This is the most important non-web attack path in the model. It implies the system is not secured only at the API layer. The DSL recognizes protocol manipulation against the gateway as a top-tier risk.

### `Script Kiddie -> ANPR Service`

This captures opportunistic abuse and commodity exploitation against a directly exposed or indirectly reachable edge service.

### `Nation State Actor -> Edge AI Runtime`

This is the AI-security signal in the architecture. The model explicitly acknowledges model poisoning and advanced adversarial risk against edge inference.

### Insider paths

The three insider targets are exactly the ones a security architect would care about:

- `Identity Provider` for privilege expansion
- `Secrets Manager` for credential theft
- `Data Lake` for bulk exfiltration

## Matching Dynamic Views

The DSL also defines dedicated dynamic views for:

- `ExternalAttackPaths`
- `InternalAttackPaths`
- `AttackVectorAnalysis`

References:

- [`workspace.dsl:815`](../model/workspace.dsl#L815)
- [`workspace.dsl:826`](../model/workspace.dsl#L826)
- [`workspace.dsl:835`](../model/workspace.dsl#L835)

## Architectural Conclusion

The DSL does not treat security as only “protect the API.” It models attacks against:

- public API entry points
- protocol translation at the edge
- AI runtime
- identity
- secrets
- data lake

That is the right threat spread for a smart parking platform.
