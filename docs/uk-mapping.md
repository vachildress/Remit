<!-- SPDX-License-Identifier: MIT. Copyright (c) 2026 The remit contributors. -->
# UK financial services mapping

**Status: stub. To be completed in weekend 7.** This file records the intended mappings so the intent is fixed before any logic is built on them. Nothing in the code acts on these fields yet: tier ceilings and "restoring a grant needs a human attestation" are weekend 2 work.

| remit evidence | UK framework | Intended role | Field in the model today |
|---|---|---|---|
| `human_attestation` | SM&CR senior manager sign-off | A named senior manager, by SMF role and function, attests to what the agent may do. The attestation carries an expiry and must be renewed. | `strength.person`, `strength.role`, `strength.attests_to`, optional `strength.smf_function`; `expires_at` |
| `standards_evidence` tier | PRA SS1/23 model risk tier | The model's risk tier sets a ceiling: no capability may exceed the level allowed for that tier, whatever other evidence exists. | optional `strength.tier` |
| `monitor_health` | Consumer Duty outcome monitoring | Consumer outcome monitoring feeds a monitor. When outcomes degrade, the capabilities that depend on that monitor contract automatically. | `strength.monitor_name`, `strength.state`, `strength.last_heartbeat`, `strength.effectiveness` |

## To do in weekend 7

- The tier to ceiling table for SS1/23, and the age limit for `standards_evidence` at each tier.
- Which SMF functions may attest to which capabilities.
- What "healthy" means for a Consumer Duty outcome monitor, and which consumer switching agent capability depends on it.
- Re-check prior art before writing any claim of novelty.
