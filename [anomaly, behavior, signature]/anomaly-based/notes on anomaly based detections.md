- Anomaly based detections look for statistical outliers
- Assumes that normal has a specific shape and anything that breaks that shape is a threat - even if the action itself seems harmless

## Pros
- Catching Insider Threats: great for catching a disgruntled employee who has legitimate access but is suddenly downloading the entire client database
- Zero-Day Network Attacks: Can spot a new worm spreading across the network because the "Connection Count" per second will skyrocket compared to normal traffic
- No Rules Required: You don't have to tell the system what to look for, it learns the enviroment on its own

## Cons
- The Training Period: if you start the system while an attacker is already in the network the system will learn the "hacker activity" as being normal
- High False Postives: Anything unusual triggers it, A simple software update or a user working late on a big project can set off alarms
- Black Box Problem: it can be hard for an analyst to understand why the AI flagged something