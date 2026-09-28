/** `solongate policy …` - manage policies, rules and the active pin. */
import { api } from '../api-client/index.js';
import type { PolicySet } from '../api-client/index.js';
import { flagBool, flagStr, parse } from './args.js';
import { bold, cyan, decisionColor, dim, err, green, printJson, table, truncate, unknownSub, usage } from './format.js';

const USAGE = usage('solongate policy', 'manage policies', [
  ['policy list', 'list all policies'],
  ['policy create <name>', 'create a new empty policy'],
  ['policy delete <id>', 'delete a policy'],
  ['policy show <id>', 'show one policy (rules, mode)'],
  ['policy allow <id> [--command|--path|--filename|--url <val>]', 'append an ALLOW rule'],
  ['policy deny  <id> [--command|--path|--filename|--url <val>]', 'append a DENY rule'],
  ['policy revoke <id> <ruleId>', 'remove a rule'],
  ['policy active', 'show the resolved active policy'],
  ['policy mode <id> <denylist|whitelist>', 'switch deny-by-default / allow-by-default'],
  ['policy rule <id> <ruleId> <enable|disable>', 'turn one rule on or off without deleting it'],
  ['policy activate <id> | --off', 'pin the active policy, or enforce nothing'],
], 'Add --json to any read command for machine-readable output.');

export async function run(argv: string[]): Promise<number> {
  const { positionals, flags } = parse(argv);
  const sub = positionals[0];
  const json = flagBool(flags, 'json');

  switch (sub) {
    case undefined:
    case 'help':
      err(USAGE);
      return sub ? 0 : 1;

    case 'list': {
      const { policies } = await api.policies.list();
      if (json) return printJson(policies), 0;
      if (policies.length === 0) {
        err(dim('  No policies. `solongate policy create <name>` makes one.'));
        return 0;
      }
      table(
        ['ID', 'NAME', 'MODE', 'RULES', 'UPDATED BY'],
        policies.map((p) => [
          cyan(p.id),
          truncate(p.name, 28),
          p.mode === 'whitelist' ? green('whitelist') : 'denylist',
          String(p.rules?.length ?? 0),
          dim(truncate(p.created_by || '-', 20)),
        ]),
      );
      return 0;
    }

    case 'show': {
      const id = positionals[1];
      if (!id) return err('  Usage: policy show <id>'), 1;
      const p = await api.policies.get(id);
      if (json) return printJson(p), 0;
      err('');
      err(`  ${bold(p.name)} ${dim(`(${p.id})`)}`);
      if (p.description) err(`  ${dim(p.description)}`);
      err(`  mode: ${p.mode === 'whitelist' ? green('whitelist') : 'denylist'}   rules: ${p.rules.length}`);
      err('');
      printRules(p.rules);
      return 0;
    }

    case 'create': {
      const name = positionals.slice(1).join(' ').trim();
      if (!name) return err('  Usage: policy create <name>'), 1;
      const res = await api.policies.create({ id: `policy-${Date.now()}`, name, rules: [], mode: 'denylist' });
      if (json) return printJson(res), 0;
      err(green(`  ✓ Created "${name}"`) + dim(` (${res.id})`));
      return 0;
    }

    case 'delete': {
      const id = positionals[1];
      if (!id) return err('  Usage: policy delete <id>'), 1;
      const res = await api.policies.remove(id);
      if (json) return printJson(res), 0;
      err(green(`  ✓ Deleted ${res.policy_id}`));
      return 0;
    }

    case 'allow':
    case 'deny': {
      const effect = sub === 'allow' ? 'ALLOW' : 'DENY';
      const id = positionals[1];
      if (!id) return err(`  Usage: policy ${sub} <id> [--command|--path|--filename|--url <val>]`), 1;
      const toolPattern = '*';
      let kind: 'command' | 'path' | 'filename' | 'url' | 'tool' = 'tool';
      let value: string | undefined;
      for (const k of ['command', 'path', 'filename', 'url'] as const) {
        const v = flagStr(flags, k);
        if (v !== undefined) {
          kind = k;
          value = v;
        }
      }
      // Permission scoping, which until now was reachable only from the
      // dataroom -- so a rule set could not be written down as commands, which
      // is what a runbook and a CI check both need.
      //
      // The class comes from the TOOL NAME, so this says which tools a rule
      // covers, not what the call does: Codex has no read tool and shells out
      // instead, so a READ-scoped rule matches nothing there, and Antigravity's
      // URL tool is `read_url_content`, which classifies as READ rather than
      // NETWORK. Scope by constraint unless you mean "only calls made with this
      // kind of tool".
      let permission: string[] | undefined;
      const rawPerm = flagStr(flags, 'permission');
      if (rawPerm !== undefined) {
        const known: Record<string, string> = { read: 'READ', write: 'WRITE', execute: 'EXECUTE', network: 'NETWORK' };
        const out: string[] = [];
        for (const part of rawPerm.split(',')) {
          const t = part.trim();
          if (!t) continue;
          const name = known[t.toLowerCase()];
          // A permission the guard has no name for would be stored, never match,
          // and leave a rule that reads correctly and enforces nothing.
          if (!name) return err(`  Unknown permission "${t}". One or more of: READ, WRITE, EXECUTE, NETWORK`), 1;
          if (!out.includes(name)) out.push(name);
        }
        if (out.length) permission = out;
      }

      const res = await api.policies.addRule(id, { toolPattern, kind, value, effect, permission });
      if (json) return printJson(res), 0;
      if (res.deduped) err(green('  ✓ ') + dim(`Equivalent ${effect} rule already present.`));
      else err(green(`  ✓ ${effect} rule added`) + dim(` (${res.rule?.id})`));
      return 0;
    }

    case 'mode': {
      // The mode was a dataroom toggle, so a whitelist policy could not be set
      // up from a script at all -- and whitelist is the mode with the most
      // consequential default: nothing is allowed until a rule says so.
      const id = positionals[1];
      const mode = (positionals[2] ?? '').toLowerCase();
      if (!id || (mode !== 'denylist' && mode !== 'whitelist')) {
        return err('  Usage: policy mode <id> <denylist|whitelist>'), 1;
      }
      const p = await api.policies.get(id);
      const saved = await api.policies.update(id, { ...p, mode } as PolicySet);
      if (json) return printJson(saved), 0;
      err(green(`  ✓ ${saved.id} is now a ${mode} policy`));
      if (mode === 'whitelist' && (saved.rules?.length ?? 0) === 0) {
        err(dim('    It has no ALLOW rules, so it currently blocks everything.'));
      }
      return 0;
    }

    case 'rule': {
      // Turning a rule off without deleting it: the dataroom has always had
      // this and the CLI had only revoke, which loses the rule.
      const id = positionals[1];
      const ruleId = positionals[2];
      const action = (positionals[3] ?? '').toLowerCase();
      if (!id || !ruleId || (action !== 'enable' && action !== 'disable')) {
        return err('  Usage: policy rule <id> <ruleId> <enable|disable>'), 1;
      }
      const p = await api.policies.get(id);
      const rules = (p.rules ?? []) as unknown as Array<Record<string, unknown>>;
      const target = rules.find((r) => r.id === ruleId);
      if (!target) {
        err(`  No rule "${ruleId}" in ${id}`);
        if (rules.length) {
          err(dim('  Rules in this policy:'));
          for (const r of rules) err(`    ${dim('•')} ${String(r.id)}`);
        }
        return 1;
      }
      // Spread rather than rebuild: a rule may carry fields this version does
      // not model, and a newer dashboard is exactly what puts one there.
      const next = rules.map((r) => (r.id === ruleId ? { ...r, enabled: action === 'enable' } : r));
      const saved = await api.policies.update(id, { ...p, rules: next } as unknown as PolicySet);
      if (json) return printJson(saved), 0;
      err(green(`  ✓ Rule ${ruleId} ${action}d`));
      return 0;
    }

    case 'revoke': {
      const id = positionals[1];
      const ruleId = positionals[2];
      if (!id || !ruleId) return err('  Usage: policy revoke <id> <ruleId>'), 1;
      const res = await api.policies.revokeRule(id, ruleId);
      if (json) return printJson(res), 0;
      err(green(`  ✓ Revoked ${ruleId}`));
      return 0;
    }

    case 'active': {
      const a = await api.policies.active();
      if (json) return printJson(a), 0;
      if (!a.policy) {
        err(dim('  No active policy resolves for this project.'));
        return 0;
      }
      err('');
      err(`  Active: ${bold(a.policy.name)} ${dim(`(${a.policy.id})`)}`);
      err(`  matched by: ${cyan(a.matched_by ?? '-')}   self-protection: ${a.self_protection_enabled ? green('on') : dim('off')}`);
      const rl = a.security?.rateLimit;
      if (rl) err(`  rate limit: ${rl.perMinute}/min  ${rl.perHour}/h  ${rl.perDay}/day`);
      if (a.security?.dlpBlock) err(`  DLP block: ${a.security.dlpBlock.patterns.length} patterns`);
      return 0;
    }

    case 'activate': {
      // `--off` does not return the project to automatic selection. An empty
      // policyId makes the server store its `__none__` sentinel, which means
      // "this project enforces nothing" -- a different state from having no
      // override at all, and there is no route back to the latter short of
      // pinning a policy again. Calling that "cleared the pin" sent people
      // looking for a policy that had in fact been switched off.
      if (flagBool(flags, 'off') || flagBool(flags, 'clear')) {
        const res = await api.policies.setActive(null);
        if (json) return printJson(res), 0;
        err(green('  ✓ Deactivated - this project now enforces no policy.'));
        err(dim('    Pin one again with: solongate policy activate <id>'));
        return 0;
      }
      const id = positionals[1];
      if (!id) return err('  Usage: policy activate <id>  |  policy activate --off'), 1;
      const res = await api.policies.setActive(id);
      if (json) return printJson(res), 0;
      err(green(`  ✓ Pinned active policy → ${res.active}`));
      return 0;
    }

    default:
      return unknownSub('policy', sub, USAGE);
  }
}

function printRules(rules: PolicySet['rules']): void {
  if (rules.length === 0) return void err(dim('  (no rules)'));
  table(
    ['EFFECT', 'PRIO', 'ID', 'DESCRIPTION'],
    rules.map((r) => [
      r.effect === 'ALLOW' ? green('ALLOW') : decisionColor('DENY'),
      String(r.priority),
      dim(r.id),
      truncate(r.description || '-', 40),
    ]),
  );
}

