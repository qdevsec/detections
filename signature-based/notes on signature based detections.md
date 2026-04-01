- Signature based detections looks at what the thing is
- Relies on a library of "digital fingerprints" to identify known threats instantly
- In signature-based detection we look for static identifiers like [`File-Hashes`, `IP Addresses`, `Domains`, `Network/Host Artifacts`]

## Pros
- very fast, simple string or hash matching takes very little processing power
- low false positives, it a unique hash is known to be a virus, there is almost no chance it is a "false alarm"

## Cons:
- fragile, if the attacker changes the file slightly (polymorphism), the signature becomes useless
- reactive, it only catches `known` threats. It can't stop a "Zero-Day" (a brand new attack no one has seen before)

Good to chain with behavioral detections, signature based detections address known malware while behavioral detections focus on sophisticated, unknown patterns.