# Legal documents (DOCS LINKS ONLY — drafts, nothing copied)
The Legal Chief bot (not a lawyer) drafted the legal set v1. **Everything is a DRAFT, has not been reviewed by an attorney, and nothing is signed or sent.**
- Set and index: <legal-docs>/README.md
- Developer agreement (includes §7A devbridge isolation, §11.2 termination, and "Revocation and Exit": return/destroy within [7] days, seal then erase after [30] days, legal-hold carve-out, audit log kept with hashes only): <legal-docs>/developer-agreement.md
- Developer data protection addendum (Schedule F): <legal-docs>/developer-data-protection-addendum.md
- Contributor license agreement, AUP, security & responsible disclosure, mutual NDA: same folder.

## Code ↔ contract alignment (needs Legal Chief)
- Agreement §7A.9 still says "there is currently no key-revocation or rotation process." The code now has revoke, seal and hold. Rotate and erase exist but are **BETA-DISABLED**. §7A.9 needs an update; this template did not edit it.
- "Seal then erase after [30] days": the code enforces a hard 30-day minimum and a legal-hold block. Erase is disabled in the beta, so sealed data is held until a non-beta build is approved.
- We cannot erase anything on a developer's machine. Revocation makes their copies useless against our system, and return/destroy is contractual.
