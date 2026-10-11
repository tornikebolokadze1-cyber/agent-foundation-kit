---
id: orchestration-guide
type: guide
title: ორკესტრაცია — maker/checker ციკლები (გამორთულია)
---

# ორკესტრაცია (maker / checker)

**სურათი:** ერთი მოდელი ქმნის (maker), მეორე — სხვა კომპანიის — ამოწმებს (checker). ერთი და იმავე მოდელის ორჯერ გაშვება „მეორე აზრი" არ არის, სხვა ოჯახის მოდელი კი სხვაგან ხედავს ბრმა წერტილებს. გადაწყვეტილება: [[ADR-0005-maker-checker-orchestration]].

**სტატუსი: ჩადებულია და გამორთულია** (`config.toml` → `enabled = false`). ჩართვა მფლობელის გადაწყვეტილებაა, შემდეგ ეტაპზე (წინადადება P-001).

| ციკლი | maker | checker | ბრუნები | რას აბრუნებს |
|---|---|---|---|---|
| არქიტექტურა | Claude Fable 5.1 | ChatGPT Astra (`gpt-6-astra`) | 1 — წინადადება → აუდიტი და პოზიცია → სინთეზი | ADR-ის პროექტი (`proposed`), მფლობელი წყვეტს `/approve`-ით |
| კოდი | Claude Opus 5 (თავად სესია) | ChatGPT Sol (`gpt-5.6-sol`) | მაქს. 2 შემოწმება ერთ ამოცანაზე | `VERDICT: approve / changes-requested / blocked` |

## ბრძანებები

```bash
py -3.12 orchestration/run.py status                                   # რა მდგომარეობაშია (ასევე /orchestrate)
py -3.12 orchestration/run.py arch --topic "რომელი არხით დავიწყოთ?" --dry-run
py -3.12 orchestration/run.py code-check --plan PLAN-0001 --task T3 --dry-run
```

`--dry-run` არცერთ მოდელს არ იძახებს და არაფერს წერს — აჩვენებს, რა გაეშვებოდა. ნამდვილი გაშვება (ჩართვის შემდეგ) ყოველ ჯერზე მფლობელს ეკითხება (permissions: ask).

## როგორ მუშაობს

- **ChatGPT:** `codex exec` (Codex CLI), ავტორიზაცია — `codex login` ChatGPT-ის გამოწერით; API გასაღები პროექტში არ ინახება. checker მუშაობს `read-only` რეჟიმში — რეპოს კითხულობს, ვერაფერს ცვლის.
- **Claude (Fable):** `claude -p --restricted` მხოლოდ კითხვის ინსტრუმენტებით (`Read, Grep, Glob`).
- **ჩანაწერები:** `orchestration/runs/<თარიღი>-<ციკლი>-…/` — prompt-ები, პასუხები, `meta.json`. ბრუნების ლიმიტი ამ ჩანაწერებიდან ითვლება, ამიტომ სესიებს შორისაც მოქმედებს. ჩავარდნილი გაშვება ბრუნს არ ხარჯავს.
- **prompt-ები:** `prompts/` — maker, checker, სინთეზი, კოდის checker. checker-ები [[REVIEW]]-ის სიმძიმის სკალასა და ფორმატს იყენებენ.
- **კარიბჭეები ციკლზე მაღლა დგას:** checker-ის „approve" ჩავარდნილ gate-ს ვერ გადაფარავს ([[ADR-0006-deterministic-gates-and-evals]]).

**exit კოდები:** `0` წარმატება · `1` ნაბიჯი ჩავარდა · `3` გამორთულია · `4` ბრუნების ლიმიტი ამოიწურა · `5` არასწორი შეყვანა.
