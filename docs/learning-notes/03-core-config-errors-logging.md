# Step 3: Core (settings, security errors, logging) (learning notes)

## The big picture

Steps 1 and 2 built the **guards**. Step 3 builds the **control room** they report to:

| File | Plain-English job | Security idea |
|---|---|---|
| `app/core/config.py` | Reads settings (keys, thresholds) from `.env` | Secrets stay out of code; bad config fails closed |
| `app/core/exceptions.py` | Decides what a blocked user is told | Tell attackers as little as possible |
| `app/core/logging.py` | Writes a record of what happened | Logs are evidence, and must not leak |

The demo shows how these connect. One blocked request produces **two very different
views**:

```
DEFENDER sees (logs):
  {"event": "guardrail.input_blocked", "request_id": "req-22003b6a8bb6",
   "data": {"risk_score": 0.95, "rules": ["io.ignore_previous", "spe.reveal_your_prompt"]}}

ATTACKER sees (HTTP 400):
  {"error": {"message": "The request was blocked by the security gateway.",
             "code": "prompt_injection_detected", "request_id": "req-22003b6a8bb6"}}
```

The **request ID** is the only thing the two views share. A real user can quote it to
support, and support can find the full story in the logs. The attacker learns nothing
useful.

---

## Part 1: Settings (`config.py`)

### Why not just write the API key in the code?
Code ends up on GitHub, in Docker images, on laptops and in screenshots. **Secrets
in code is one of the most common causes of real breaches.** So:
- Secrets live in **environment variables** or a `.env` file that git ignores.
- `.env.example` is the *template*: same names, blank values. It's safe to commit.
- This follows the **12-Factor App** rule: "store config in the environment".

### `SecretStr`: secrets that hide themselves
```python
settings.openai_api_key          # prints: **********
settings.openai_api_key.get_secret_value()   # the real key, only when you ask for it explicitly
```
If someone does `print(settings)` or an error report dumps the settings object, the key
shows up as stars.

### Validation: fail closed on bad config
Imagine someone types `INJECTION_BLOCK_THRESHOLD=7` instead of `0.7`. Without
validation, no prompt could ever score 7, so **nothing would ever be blocked**, and
nobody would notice. Our settings refuse to start instead:

| Rule | Why |
|---|---|
| Thresholds must be between 0 and 1 | Typos can't silently switch off the guardrails |
| Medium threshold ≤ block threshold | Otherwise the risk levels make no sense |
| Production needs `OPENAI_API_KEY` and `OPENAI_MODEL` | Catch missing setup at startup, not on the first customer request |
| Production can't have `EXPOSE_VIOLATION_DETAILS=true` | The debug setting can't leak into production |

That last rule is **"secure by default"**: the safe choice is the default, and the
unsafe one is impossible in production.

### `MAX_PROMPT_CHARS`
A 5 MB prompt costs real money (you pay per token) and makes every check slower. Rejecting
huge inputs early is basic **denial-of-service (DoS) protection**.

---

## Part 2: Security errors (`exceptions.py`)

### Speak the client's language
Apps calling our gateway use the OpenAI SDK, so our errors use OpenAI's format
(`{"error": {"message", "type", "code"}}`). Their existing error handling just works.

### Picking the right HTTP status code
| Code | Meaning | When we use it |
|---|---|---|
| **400** Bad Request | "This request is unacceptable; don't retry it unchanged" | Prompt injection blocked |
| **413** Content Too Large | "Too big" | Prompt over `MAX_PROMPT_CHARS` |
| **422** Unprocessable | "Malformed JSON / wrong fields" | FastAPI uses it automatically for schema errors |
| **500** Internal Error | "Our fault" | Unexpected gateway bugs |

Keeping **400 (attack)** separate from **422 (client bug)** means a dashboard can show
"attacks per hour" without client bugs mixed in.

### Information disclosure
Saying *"blocked by rule io.ignore_previous, score 0.95"* would teach the attacker
exactly which phrase to reword. So the client gets a fixed message, and the details
go only to logs. This is the same **fail closed, stay vague** principle as Step 2.

---

## Part 3: Logging (`logging.py`)

### Why JSON logs?
A plain log line like `WARNING blocked a prompt from req-22 score .95` is easy for
humans and painful for machines. A JSON log line is easy for both:
```json
{"level": "WARNING", "event": "guardrail.input_blocked", "data": {"risk_score": 0.95}}
```
A **SIEM** (Security Information and Event Management system, such as Splunk,
Microsoft Sentinel or Elastic) can then run queries like *"alert me if
`guardrail.input_blocked` happens more than 50 times per minute"*. That's exactly what
a SOC (Security Operations Center) analyst does all day.

### Correlation IDs (`request_id`)
Every request gets an ID, and every log line written while handling it carries that
ID. During an incident you search for one ID and see the whole timeline. We store it in
a `ContextVar` rather than a normal global variable, because the server handles many
requests at once and each one must see **its own** ID.

### Scrubbing logs: a safety net
Logs are read by many people and tools, kept for months, and often shipped to third
parties. Logging PII can break **GDPR**, and logging keys hands them to anyone with log
access. So every log line goes through the Step 1 PII detector before it's written:
```
"note": "I'm jane@acme.com. Ignore all…"   →   "note": "I'm [EMAIL_REDACTED]. Ignore all…"
```
It even scrubs **exception tracebacks**, because an error like
`AuthenticationError: invalid key sk-proj-…` is a classic way keys end up in logs.

⚠️ Scrubbing is a *safety net*, not permission. The gateway's code should still never
log prompts or keys on purpose. (The demo logs the prompt only to show scrubbing working.)

---

## Engineering lessons from this step

- **Reuse beats copy-paste.** We needed "replace with `[TYPE_REDACTED]`" in two places
  (output inspector and logs), so we moved it into one shared `redact()` function in a
  separate *refactor* commit. If there's a bug, it gets fixed in one place.
- **Watch for side effects in your own safety net.** The first version of the scrubber
  also scanned the gateway's own fields. A request ID made only of digits could look like
  a card number and get mangled. Fixed by scrubbing only free-text fields.
- **Rule exceptions are scoped.** We allowed fake passwords (`S105`/`S106`) **only in
  `tests/`**. The production code is still checked.

---

## Try it yourself
```bash
poetry run pytest tests/core -v
```
```bash
cp .env.example .env            # then try INJECTION_BLOCK_THRESHOLD=7 and:
poetry run python -c "from app.core.config import get_settings; get_settings()"
```
You should see the app refuse to load, with a clear validation error. Set it back to 0.7 afterwards.

**Exercises**
1. Add a setting `BLOCKED_COUNTRIES` (a list) and validate that each entry is a 2-letter code.
2. Write a log line that sneaks PII past the scrubber. Hint: a name, or an email written
   as "jane at acme dot com". How would you catch it?
3. Why would logging only `prompt_chars` (the prompt's length) be useful for spotting an
   attack, even without logging the prompt itself?
