# AGENTS.md

## Working style: pstack (poteto-mode)

This repo vendors pstack at `.cursor/skills/pstack/` (MIT, from cursor/plugins). Model roles are in `.cursor/rules/pstack-models.mdc`.

- For any nontrivial task (a bug fix, feature, refactor, perf work, investigation, multi-file change, or anything the prompt calls rigorous), use `/poteto-mode` before you do anything else. If the skill was not attached to the prompt, read `.cursor/skills/pstack/poteto-mode/SKILL.md` in full and follow it. It has `disable-model-invocation: true`, so it will not load by itself.
- You, the agent that received the task, run the playbook. Spawn delegates with `subagent_type: "poteto-agent"` (defined in `.cursor/agents/poteto-agent.md`) and put the absolute path of `.cursor/skills/pstack/poteto-mode/SKILL.md` in every delegate brief.
- Skip pstack for trivial edits: typos, version bumps, one-line config changes.
- Not vendored here: `deslop`, `control-ui`, `control-cli` (cursor-team-kit). When poteto-mode asks for them, skip the step and say so.

### Cursor Cloud specific instructions

- You run on a cloud VM. There is no `~/.cursor/plugins/` or `~/.cursor/rules/`. Use the repo paths above.
- pstack's `poteto-mode/scripts/watch-pr/watch-pr` and `scripts/orch/orch.ts` need Bun. Before using them, run `command -v bun || bash .cursor/pstack-env.sh`, then `export PATH="$HOME/.bun/bin:$PATH"`. Bun may be missing on a fresh environment whose first Build hasn't finished, because agents boot the default image until then. If the install fails, fall back to `gh pr view` / `gh pr checks` and say so.
- Open a PR for review. Do not merge, force-push shared branches, or change repository settings unless the prompt says so.
