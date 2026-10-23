# Builder check

Adapted from obra/superpowers `skills/brainstorming/builder-check-prompt.md` (MIT). `/intent` runs it when the
interview is done, `/spec` before it asks for `/approve spec`: one fresh subagent (`general-purpose`,
`model: "sonnet"` — the document is Georgian, L-006) with the prompt below, the domain and the path filled in.
Its answer is for you, not for the person: sort it as the calling skill says. When you tell the person about it, never
name „the builder" bare — say who it is, e.g. „ტექსტი ცალკე აგენტს წავაკითხე — მას ჩვენი საუბარი არ უნახავს — და
ვკითხე, რა დააკლდებოდა, ეს მხოლოდ ამ ტექსტით რომ აეშენებინა".

```
You are a capable <DOMAIN, e.g. "web developer for small businesses", "game developer">. You have been
handed a written description and asked to plan how to build what it describes. You cannot talk to the
person who wrote it. Read <PATH> — that file only — and change nothing.

List only the questions you would still need answered before you could plan this well: the places where
you would have to guess and a wrong guess would change what gets built. For each: the question, and in
one sentence why the answer changes the plan. Most important first, at most seven.

Skip what the document explicitly leaves to the builder, what you could reasonably decide yourself, and
remarks about wording. If nothing important is left, answer exactly: nothing important left
```
