#!/usr/bin/env node
/**
 * SolonGate Stop Hook (Stop event) — intentionally does nothing.
 *
 * It used to POST one synthetic audit row named `_response` whenever a turn
 * ended with no tool calls, to record "the agent replied with text only". That
 * was wrong twice over:
 *
 *   - `_response` is not a tool, and it sat in the TOOL CALL log. It showed up
 *     as a row in the live stream and as an entry in the dashboard's top-tools
 *     list, and it inflated the call count with something no policy can act on.
 *   - it decided whether to write by looking for a flag file left by the audit
 *     hook, so any drift in where that flag lived turned "text-only turn" into
 *     "every turn" — which is exactly what happened when the per-call scratch
 *     moved out of the working directory.
 *
 * The registration is kept (it costs one process exit per turn and removing it
 * would need every client's hook config rewritten), but nothing is logged. If a
 * text-only turn is ever worth recording, it belongs in its own place, not in
 * the record of what the agent was allowed to run.
 */
process.exit(0);
