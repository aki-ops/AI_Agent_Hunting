# CLAUDE.md

Behavioral guidelines cho AI agent khi làm việc với project này. Dựa trên [Andrej Karpathy's observations](https://x.com/karpathy/status/2015883857489522876) về LLM coding pitfalls, được adapt cho project Threat Investigation Agent.

**Tradeoff:** Các guidelines này thiên về cẩn thận hơn là nhanh. Với task đơn giản (typo, one-liner), dùng phán đoán — không cần full rigor cho mọi thay đổi.

---

## 1. Think Before Coding

**Đừng giả định. Đừng giấu confusion. Surface tradeoffs.**

Trước khi implement:
- State assumptions explicitly. Nếu không chắc, **hỏi thay vì đoán**.
- Nếu nhiều cách hiểu tồn tại, **trình bày tất cả** — đừng chọn im lặng.
- Nếu có cách đơn giản hơn, nói ra. Push back khi cần.
- Nếu không rõ, **dừng lại**. Nêu rõ điều gì gây confusion. Hỏi.

### Project-Specific
- Kiến trúc đã **FROZEN** — không redesign, chỉ implement.
- Nếu phát hiện conflict giữa design document và thực tế implementation, **báo cáo conflict**, không tự ý sửa architecture.
- Phân biệt rõ giữa LOCKED / PROVISIONAL / UNSUPPORTED / REJECTED (xem context.md §12).

---

## 2. Simplicity First

**Code tối thiểu giải quyết vấn đề. Không gì speculative.**

- Không features vượt yêu cầu.
- Không abstractions cho single-use code.
- Không "flexibility" hay "configurability" chưa được yêu cầu.
- Không error handling cho impossible scenarios.
- Nếu viết 200 dòng mà có thể 50, viết lại.

Tự hỏi: *"Senior engineer sẽ nói code này overcomplicated?"* Nếu có, simplify.

### Project-Specific
- LLM calls target: **8–16 per investigation**. Mọi thiết kế phải giữ hoặc giảm con số này.
- Mọi thứ có thể deterministic **PHẢI** deterministic — xem LLM Boundary table trong context.md §7.
- Không thêm probabilistic/Bayesian/RL/POMDP machinery — đã bị **REJECTED**.

---

## 3. Surgical Changes

**Chỉ đụng vào cái cần đụng. Chỉ dọn mess mình tạo ra.**

Khi sửa code existing:
- Đừng "improve" adjacent code, comments, hay formatting.
- Đừng refactor thứ chưa hỏng.
- Match existing style, dù bạn sẽ làm khác.
- Nếu thấy unrelated dead code, **mention nó** — đừng xóa.

Khi thay đổi tạo orphans:
- Remove imports/variables/functions mà **THAY ĐỔI CỦA BẠN** làm unused.
- Đừng remove pre-existing dead code trừ khi được yêu cầu.

**Test: Mọi dòng thay đổi phải trace trực tiếp về request của user.**

### Project-Specific
- **KHÔNG BAO GIỜ** remove hay modify existing comments/docstrings trừ khi trực tiếp liên quan đến code change.
- Giữ nguyên tất cả provenance annotations (`[MEASURED]`, `[LIT]`, `[UNTESTED]`, `[KILLED]`).
- Append-only cho audit logs — không delete hay overwrite mid-investigation data.

---

## 4. Goal-Driven Execution

**Định nghĩa success criteria. Loop cho đến khi verified.**

Transform tasks thành verifiable goals:
- "Add validation" → "Write tests for invalid inputs, then make them pass"
- "Fix the bug" → "Write a test that reproduces it, then make it pass"
- "Refactor X" → "Ensure tests pass before and after"

Cho multi-step tasks, state brief plan:
```
1. [Step] → verify: [check]
2. [Step] → verify: [check]
3. [Step] → verify: [check]
```

Strong success criteria cho phép loop independently. Weak criteria ("make it work") đòi hỏi constant clarification.

### Project-Specific
- Mỗi module có **Definition of Done** rõ ràng trong EXECUTION-PLAN.md §3.
- MVP gate: **full loop chạy end-to-end với ZERO LLM calls** trước khi thêm M2.
- Mỗi experiment có **kill criterion** — nếu trigger, phải thay đổi architecture tương ứng.

---

## 5. Security-First Development

> Project-specific principle — **critical vì đây là security tool xử lý adversarial data**.

### Hard Rules (Non-Negotiable)
- **LLM KHÔNG BAO GIỜ nhận raw log `content` field** — static + runtime check (M-02)
- **B-04 hidden-target guard**: hard-block `attack_step`, `step_description`, tactic/technique labels, `causal_edges`, support mapping khỏi mọi query/prompt
- **Taint labelling (C-03)**: mọi field phải được label `ATTACKER_INFLUENCED` hoặc `STRUCTURAL`
- **Prompt input filter (E-02)**: chỉ extracted fields + taint labels vào prompt
- **Attribution bookkeeping**: `attributed_by` KHÔNG BAO GIỜ writable bởi M2 output
- **`STOP_RESOLVED`**: KHÔNG BAO GIỜ reachable qua bất kỳ LLM output path nào

### Injection Defense
- Taint gate: attribution resting solely trên attacker-influenced fields → `TAINTED`
- Template-first queries: common intents dùng hand-written templates, không LLM
- Reporter nhận observation IDs, không raw logs

---

## 6. Evidence & Provenance Discipline

> Project-specific principle — **mọi claim phải traceable**.

### Rules
- Mọi design decision phải tagged: `[MEASURED]`, `[LIT]`, `[UNTESTED]`, `[KILLED]`
- Không cite reference đang ở status `UNVERIFIED`
- Provenance classes: `INHERITED`, `ADAPTED`, `COMPOSED`, `ORIGINAL`, `EXPERIMENTALLY-DERIVED`, `ENGINEERING`
- **Null baselines bắt buộc** trong mọi retrieval experiment (IDF null, length null, random)
- Nếu một mechanism bị `KILLED` bởi experiment, nó **KHÔNG ĐƯỢC re-enter** mà không có evidence mới

### Claim Status Discipline
- `ESTABLISHED`: đã measured, replicated, hoặc multiply supported
- `PROVISIONAL`: measured nhưng n nhỏ hoặc chưa replicated — **không overclaim**
- `UNSUPPORTED`: design hợp lý nhưng chưa measured — **không claim validated**
- `FUNDAMENTALLY UNRESOLVED`: thesis phải state explicitly

---

## 7. Testing Standards

### Mỗi component phải có:
- **Unit tests**: known-answer fixtures, state-machine transitions
- **Integration tests**: full loop trên synthetic incident + CDB chain
- **Security tests** (trước khi LLM chạm real logs):
  - S1–S4 injection payloads trong command lines, URLs, DNS, usernames, filenames
  - Assert raw `content` never in any prompt
  - Assert `attributed_by` never writable by M2
  - Assert `STOP_RESOLVED` unreachable via LLM output path
  - Assert B-04 guard raises trên mọi withheld field
- **Regression tests**: một test per historical failure (E1b leakage, E4 IDF-null, E6 OF-below-random, E3 trigger precision)

---

## 8. Code Style & Conventions

- Python 3.10+, fully typed
- CI green trước merge
- Deterministic seeding: mọi run phải reproducible (git SHA + config hash + seed)
- LLM client: tất cả calls qua cached client với call/token counter
- Append-only audit log: mọi state transition (actor, precondition, delta)

---

## How to Know Guidelines Are Working

Các guidelines đang hoạt động nếu:
- ✅ Fewer unnecessary changes in diffs — chỉ requested changes xuất hiện
- ✅ Fewer rewrites do overcomplication — code đơn giản lần đầu
- ✅ Clarifying questions đến **trước** implementation — không phải sau mistakes
- ✅ Clean, minimal PRs — không drive-by refactoring
- ✅ Security boundaries respected — không raw logs trong prompts
- ✅ Evidence status maintained — claims properly tagged
