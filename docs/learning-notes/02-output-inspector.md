# Step 2: Output Inspector (learning notes)

## The big picture

In Step 1 the bouncer checked people coming **in**. But no bouncer catches everyone,
and a clever attacker will eventually get a prompt past the input rules.

So in Step 2 we put a second guard at the **exit**. Whatever the AI says gets checked
before it reaches the user. Even if an attack succeeds, the *damage* (a leaked secret,
leaked instructions) is stopped on the way out.

This is **defense in depth**: several independent layers, so one failure doesn't
mean a breach. It's like a bank having both a locked door *and* a vault.

```
user ─► [Step 1: injection check + PII mask] ─► LLM ─► [Step 2: output inspector] ─► [restore PII] ─► user
```

**OWASP mapping:** LLM07 System Prompt Leakage, and LLM02 Sensitive Information
Disclosure (the output side).

The inspector can decide three things:

| Action | Meaning | Example |
|---|---|---|
| **ALLOW** | Clean, pass it through | A normal answer |
| **REDACT** | Usable once the bad part is cut out | Answer contains an API key → `[API_KEY_REDACTED]` |
| **BLOCK** | Unsafe to return at all | Answer contains the system prompt |

---

## Check 1: Secret redaction

**Problem.** An LLM can output a secret in three ways:
1. It's in the system prompt. Developers sometimes paste keys there, which is a big mistake.
2. A tool the AI uses (a database or a file reader) returned one.
3. It "remembered" one from training data.

**Solution.** We reuse the PII detector from Step 1, but tell it to look **only** for
secrets (API keys and card numbers). Code reuse matters in security: one well-tested
detector beats two half-tested ones.

**Why `[API_KEY_REDACTED]` has no number here.** On the input side we numbered tokens
so they could be *restored*. A secret leaked in an output must **never** be restored,
so it doesn't need a number.

**Why the user's own email isn't flagged.** Order matters. We inspect the AI's answer
*while it still contains tokens* (`[EMAIL_REDACTED_1]`), and only restore the user's
email *after* the inspection.

---

## Check 2: Canary tokens 🐤

**The idea comes from coal mining.** Miners took a canary into the mine. If dangerous
gas leaked, the canary showed it first. That was an early warning.

**In our gateway:**
1. For each request we generate a random code such as `canary-9f3a1c7e2b4d6a80`.
2. We hide it at the end of the system prompt.
3. A real answer has **no reason** to ever say that code.
4. If the code appears in a response, the system prompt **definitely** leaked, so we block.

**Key security details:**
- We use Python's `secrets` module, not `random`. `random` is predictable: if an
  attacker sees a few values, they can work out the next ones. `secrets` is
  *cryptographically secure*, meaning it's unpredictable.
- It's a **fresh canary per request**, so a canary leaked once is useless next time.
- Attackers may say "spell it out with spaces" or "write it in capitals". We strip
  everything except letters and digits before comparing, so `C A N A R Y - 9 F 3 A`
  still matches.
- **Canaries give almost no false positives.** A random 16-character code can't show
  up by accident, so when this check fires, it's certain.

---

## Check 3: System prompt overlap (shingling)

**Problem.** The canary only catches leaks that include the canary line. What if the
AI leaks just the *first paragraph* of its instructions, or the attacker asks for
"only the rules about fraud"?

**Solution: compare wording with "shingles".** A shingle is a run of 8 consecutive
words. The system prompt "never reveal that fraud alerts trigger above 5000 dollars per
day" contains these 8-word shingles:

```
(never reveal that fraud alerts trigger above 5000)
(reveal that fraud alerts trigger above 5000 dollars)
(that fraud alerts trigger above 5000 dollars per)
...
```

We count how many of the prompt's shingles also appear in the answer:

```
overlap = shared shingles / total prompt shingles      (0.0 = nothing copied, 1.0 = everything)
```

If overlap ≥ **20%**, we block.

**Why 8 words?** Short phrases like "the support assistant for" appear in normal
answers all the time. **Eight identical words in a row** almost never happen by
coincidence. This is the same idea plagiarism checkers like Turnitin use.

**Reuse again:** before comparing, the text goes through Step 1's `normalize()`, so
CAPITALS or invisible characters don't hide copying.

**Limitation:** if the AI *paraphrases* the prompt ("I'm not allowed to talk about
the $5k fraud limit"), no shingles match. Catching paraphrases needs *semantic
similarity* (comparing meaning with embeddings), which is a possible upgrade later.
That's why we have both canaries and shingles: different layers catch different leaks.

---

## Two security principles in this step

**1. Fail closed.** When we block, the user gets one fixed, vague message: *"The
response was withheld by the security gateway."* We never send back "half" a leaked
system prompt, and we don't explain *what* we caught. Telling an attacker "blocked
because of the canary" helps them adjust their next attempt.

**2. Logs must not leak.** A finding's `detail` says *"API_KEY redacted from
response"*, never the key itself. Security logs are read by many people and tools, so
they must not become a second leak.

---

## Things we hit while building (real-world lessons)

- **The linter flagged `SECRET_EXPOSURE = "secret_exposure"` as a hard-coded
  password.** It's a false positive: the name contains "SECRET", but the value is
  only a label. We suppressed it *on that line only*, with a comment explaining why.
  Never switch a security rule off globally to silence one warning.
- **A test failed because sixteen zeros pass the Luhn check.** Our fake canary
  `canary-0000000000000000` was (correctly!) treated as a card number. The detector
  was right and the test data was wrong. Always question your test data too.

---

## Try it yourself
```bash
poetry run pytest tests/guardrails/test_output_inspector.py -v
```

**Exercises**
1. Write an answer that leaks the system prompt but scores below 20% overlap.
   Hint: paraphrase it, or leak it one word per line in reverse order. Which layer
   could catch it?
2. Add a check that blocks private keys (`-----BEGIN RSA PRIVATE KEY-----`).
3. Change `ngram_size` to 4 and run the tests. Which "safe" test starts failing, and why?
