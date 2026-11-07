# KEV, EPSS and CVSS: what each signal says

| Signal | Question it answers | What it does not say | Published by |
| --- | --- | --- | --- |
| **CVSS** (0 to 10) | How bad would it be if exploited? | Whether anyone exploits it, or whether it applies to you | The vendor or NVD |
| **EPSS** (0 to 1) | How likely is exploitation in the next 30 days? | It learns from past activity, so it lags on brand-new and targeted exploitation | FIRST |
| **KEV** (list) | Is it being exploited in the wild right now? | Nothing graded: it is a yes/no, and always after the fact | CISA |
| **CSAF** (format) | Which versions are affected, which are fixed? | It is not a risk signal; it is what makes version matching automatable | The vendors |

## Why the order matters: KEV first, EPSS second, CVSS last

CVE-2026-0322 (PAN-OS, management interface RCE) was added to KEV on 2026-10-14 with a 3-day deadline, and Palo Alto flags it as attacked. Three weeks later its EPSS score was still **1.7%**.

EPSS models opportunistic, large-scale exploitation. A targeted campaign against a few edge devices produces little telemetry, so the model stays low. A tool that ranked by EPSS alone would have put this CVE near the bottom of the list. `vuln-triage` checks KEV and the vendor's own exploitation statement first.

## Why exposure decides

The same CVE-2026-0322 is critical when the management interface is reachable from the Internet, and much less so when it is restricted to trusted internal addresses. This is why the inventory records *which* part of each device is exposed, and why the scorer looks at the component the advisory targets.
