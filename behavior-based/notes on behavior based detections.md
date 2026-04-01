- for these type of detections we need a baseline of "normal" activity to contrast against "suspicious" patterns
- Behavioral detections focus on `tactics` (how attackers moves) rather than `indicators` (like a specific IP address)
- signature based detection can be used to create a no fly list, identifying things based on signatures, while behavioral based detection is concerned about what is being done

## Pros - can identify evolving threats
- Detects zero-days: looks for suspicious actions (e.g., a word document launching a hidden PowerShell script), can catch brand-new malware that doesn't have a signature 
- Hard to Bypass: even if an attacker can easily change a file's hash (signature) it is very difficult to change the behavior required to steal data becausse an attacker will have to interact with the system in a certain way to succeed
-Identifies "Living of the land" (LotL): attackers often use legitimate tools (like `vssadmin.exe` to delete backups). Signatures won't flag these since these are marked safe, behavioral rules will flag the `intent` of deleting all backups at once
- Context-Aware: behavioral detection connects the dots, one isolated action might be file, but a sequence of five actions 
    - [Scan -> Exploit -> Persist -> Dump -> Exfil]

## Cons - Can cause high "Noise" (FP) rate
- High False Postive Rate: legitimate software often behaves like malware, a backup script might look like ransomware, developer's tool might look like a credential stealer
- Resource Intensive: monitoring every process, API call, and network connection requires significant CPU and memory on the host, and massive storage in the SIEM
- Requires "Baselines": You have to spend weeks learning what "normal" looks like for every environment
- Expertise Needed: When a behavioral aler fires it's rarely a simple "Yes/No" answer 