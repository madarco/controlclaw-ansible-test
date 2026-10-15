// A meeting consult carries the whole meeting the first time and only what is new after that
// (consult-delta): live.js offers both, the patched OpenClaw consult (meeting-runtime-patch.py,
// realtime-session-harness) picks. The patch half runs the patched functions themselves, cut out
// of the pinned host archive in MEET_UPSTREAM (tests/README-meetings.md).
import './fixtures/home.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { appendFileSync, mkdtempSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { runInNewContext } from 'node:vm';
import { LiveBridge } from '../roles/controlclaw/files/meeting-voice/live.js';

// ---- live.js: what each consult carries ----

function bridge(dir) {
  const tools = [];
  const req = { providerConfig: { provider: 'gateway', model: 'openai/gpt-live-1', surface: 'meeting', wake: { enabled: false, words: ['Jarvis'] } }, onAudio: () => {}, onToolCall: t => tools.push(t), onTranscript: () => {}, onClose: () => {}, onClearAudio: () => {} };
  const b = new LiveBridge(req, { metric: () => {}, voiceDir: dir, lease: () => ({ at: '', owner: null, meetingId: 'm1', full: false, present: false }) });
  b.ws = { readyState: 1, bufferedAmount: 0, send: () => {}, terminate: () => {} }; b.ready = true;
  let n = 0;
  const ask = (q = 'Jarvis, a question?') => {
    b.event({ type: 'session.input_transcript.delta', delta: q });
    b.event({ type: 'session.delegation.created', delegation: { id: `d${++n}` } });
    return tools.at(-1);
  };
  return { b, tools, ask };
}
const at = s => new Date(Date.parse('2026-10-15T10:00:00Z') + s * 1000).toISOString();
const caption = (dir, s, speaker, text) => appendFileSync(join(dir, 'captions.jsonl'), JSON.stringify({ at: at(s), speaker, text }) + '\n');
const own = (dir, s, text) => appendFileSync(join(dir, 'meeting.jsonl'), JSON.stringify({ at: at(s), kind: 'line', role: 'assistant', text }) + '\n');
const rules = ctx => ctx.slice(0, ctx.indexOf('\n\n'));

test('the first consult carries the whole meeting; a later one only what finished since the last answer', () => {
  const dir = mkdtempSync(join(process.env.HOME, 'delta-'));
  caption(dir, 1, 'Alice', 'The launch moved to Thursday.');
  caption(dir, 2, 'Bob', 'Budget is twelve thousand.');
  const f = bridge(dir);
  const first = f.ask().args;
  assert.match(first.context, /The meeting so far[\s\S]*launch moved to Thursday[\s\S]*twelve thousand/);
  assert.equal(first.ccMeetingDelta, undefined, 'nothing is known to be in the consult session yet');

  f.b.submitToolResult('d1', { text: 'Thursday.' });
  caption(dir, 3, 'Carol', 'Marketing wants a demo video.');
  own(dir, 4, 'The launch is on Thursday.');
  const second = f.ask().args;
  assert.match(second.context, /launch moved to Thursday[\s\S]*demo video/, 'the whole meeting is still offered, for a session that turns out new');
  const delta = second.ccMeetingDelta;
  assert.match(delta, /More of the meeting since your last answer[\s\S]*Carol: Marketing wants a demo video\./);
  assert.doesNotMatch(delta, /launch moved to Thursday|twelve thousand/, 'not what the session already has');
  assert.doesNotMatch(delta, /Jarvis: The launch is on Thursday/, 'nor the agent\'s own line (OpenClaw\'s recent voice lines have it)');
  assert.equal(rules(delta), rules(second.context), 'the rules come first and unchanged, so they cache');
  assert.match(rules(delta), /^How to handle this request/);

  f.b.submitToolResult('d2', { text: 'ok' });
  const third = f.ask().args;
  assert.match(third.ccMeetingDelta, /Nothing more was said in the meeting since your last answer\./);
  f.b.close();
});

test('a failed consult is not counted, a restart starts over, a long gap sends the whole meeting', () => {
  const dir = mkdtempSync(join(process.env.HOME, 'delta-'));
  caption(dir, 1, 'Alice', 'First point.');
  const f = bridge(dir);
  f.ask(); f.b.submitToolResult('d1', { text: 'ok' });
  caption(dir, 2, 'Bob', 'Second point.');
  assert.match(f.ask().args.ccMeetingDelta, /Second point/);
  f.b.submitToolResult('d2', { error: 'Main-agent lookup failed' });
  caption(dir, 3, 'Carol', 'Third point.');
  const after = f.ask().args.ccMeetingDelta;
  assert.match(after, /Second point[\s\S]*Third point/, 'what the failed consult carried is sent again');
  f.b.close();

  // A new voice session (a restart of the voice or the gateway): nothing known, the whole meeting.
  const g = bridge(dir);
  assert.equal(g.ask().args.ccMeetingDelta, undefined);
  g.b.submitToolResult('d1', { text: 'ok' });
  for (let i = 0; i < 300; i++) caption(dir, 10 + i, 'Dave', `A long stretch of meeting, line ${i}, with enough words to add up quickly.`);
  const long = g.ask().args;
  assert.equal(long.ccMeetingDelta, undefined, 'more than the delta limit: the whole meeting instead');
  assert.match(long.context, /The meeting so far/);
  g.b.close();
});

test('a phone consult carries no meeting and no delta', () => {
  const tools = [];
  const req = { providerConfig: { provider: 'gateway', model: 'openai/gpt-live-1', surface: 'phone' }, onAudio: () => {}, onToolCall: t => tools.push(t), onTranscript: () => {}, onClose: () => {}, onClearAudio: () => {} };
  const b = new LiveBridge(req, { metric: () => {} });
  b.ws = { readyState: 1, bufferedAmount: 0, send: () => {}, terminate: () => {} }; b.ready = true;
  b.event({ type: 'session.input_transcript.delta', delta: 'check my notes' });
  b.event({ type: 'session.delegation.created', delegation: { id: 'p1' } });
  b.submitToolResult('p1', { text: 'ok' });
  b.event({ type: 'session.input_transcript.delta', delta: 'and again' });
  b.event({ type: 'session.delegation.created', delegation: { id: 'p2' } });
  assert.equal(tools[1].args.ccMeetingDelta, undefined);
  assert.doesNotMatch(tools[1].args.context ?? '', /meeting/);
  b.close();
});

// ---- the patched OpenClaw consult: which of the two it uses ----

const patched = execFileSync('python3', ['-c', `
import importlib.util, shutil, sys, tempfile, contextlib, io
from pathlib import Path
s = importlib.util.spec_from_file_location('p', 'roles/controlclaw/files/meeting-runtime-patch.py'); m = importlib.util.module_from_spec(s); s.loader.exec_module(m)
up = Path(sys.argv[1])
with tempfile.TemporaryDirectory() as d:
    root = Path(d)
    for p in m.PATCHES:
        t = root / p['kind'] / p['path']; t.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(up / ('host/package' if p['kind'] == 'host' else 'package') / p['path'], t)
    with contextlib.redirect_stdout(io.StringIO()): m.patch(root / 'host', root / 'plugin')
    spec = [p for p in m.PATCHES if 'realtime-session-harness' in p['path']][0]
    print((root / 'host' / spec['path']).read_text())
`, process.env.MEET_UPSTREAM || '/tmp/meet-upstream'], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });

function patchedFunctions() {
  const start = patched.indexOf('/** ControlClaw (consult-delta)');
  const end = patched.indexOf('async function consultRealtimeVoiceAgent(params) {');
  assert.ok(start > 0 && end > start, 'the patched helpers are in the file');
  // A fresh copy of the helpers: a fresh process, with nothing remembered.
  return runInNewContext(`${patched.slice(start, end)}; ({ ccMeetingContextChoice, ccMeetingContextRecord })`, {});
}

test('the patched prompt is built from the choice, and the record follows an answered consult', () => {
  assert.match(patched, /args: ccMeetingContext\.args,\n\t+transcript: ccMeetingContext\.transcript,/);
  assert.match(patched, /assertRealtimeVoiceConsultNotInterrupted\(abortSignal, result\.meta\);\n\t+ccMeetingContextRecord\(params, agentId, storePath, ccMeetingContext\);/);
});

const KEY = 'agent:main:subagent:google-meet:meet_1';
function runtime(entry) {
  return { session: { getSessionEntry: () => entry.current } };
}
const consult = (args, transcript = []) => ({ sessionKey: KEY, args, transcript, logger: { info: () => {} } });
const full = 'RULES\n\nTIME\n\nThe meeting so far, from its captions:\nA\nB';
const delta = 'RULES\n\nTIME\n\nMore of the meeting since your last answer:\nC';

test('first, later, reset, compaction, restart', () => {
  const { ccMeetingContextChoice: choose, ccMeetingContextRecord: record } = patchedFunctions();
  const store = { current: { sessionId: 's1', compactionCount: 0 } };
  const answered = (p, c) => record({ ...p, agentRuntime: runtime(store) }, 'main', '/store', c);
  const voice1 = [{ role: 'user', text: 'when is the launch' }, { role: 'assistant', text: 'let me check' }];

  // First consult: no record, the whole meeting (live.js offers no delta yet anyway).
  let p = consult({ question: 'q1', context: full }, voice1);
  let c = choose(p, store.current);
  assert.equal(c.used, false); assert.equal(c.args.context, full); assert.equal(c.args.ccMeetingDelta, undefined);
  answered(p, c);

  // Later, same session: the new part, and only voice lines it has not carried.
  const voice2 = [...voice1, { role: 'user', text: 'and the budget' }];
  p = consult({ question: 'q2', context: full, ccMeetingDelta: delta }, voice2);
  c = choose(p, store.current);
  assert.equal(c.used, true); assert.equal(c.args.context, delta); assert.equal('ccMeetingDelta' in c.args, false);
  assert.deepEqual(c.transcript, [{ role: 'user', text: 'and the budget' }]);
  answered(p, c);

  // Reset: a new session id. The whole meeting, and the full voice lines.
  store.current = { sessionId: 's2', compactionCount: 0 };
  p = consult({ question: 'q3', context: full, ccMeetingDelta: delta }, voice2);
  c = choose(p, store.current);
  assert.equal(c.used, false); assert.equal(c.args.context, full); assert.equal(c.transcript, voice2);
  answered(p, c);

  // Compaction since the last answer: the first message may be gone from the history.
  store.current = { sessionId: 's2', compactionCount: 1 };
  c = choose(consult({ question: 'q4', context: full, ccMeetingDelta: delta }), store.current);
  assert.equal(c.used, false);
  answered(consult({ question: 'q4', context: full }), c);
  assert.equal(choose(consult({ question: 'q5', context: full, ccMeetingDelta: delta }), store.current).used, true, 'after an answered full consult, the delta again');

  // Compaction during the run: what was recorded is dropped, the next consult sends everything.
  p = consult({ question: 'q6', context: full, ccMeetingDelta: delta });
  c = choose(p, store.current);
  assert.equal(c.used, true);
  store.current = { sessionId: 's2', compactionCount: 2 };
  answered(p, c);
  assert.equal(choose(consult({ question: 'q7', context: full, ccMeetingDelta: delta }), store.current).used, false);

  // The session gone (deleted) after a run: forgotten.
  p = consult({ question: 'q8', context: full });
  c = choose(p, store.current); answered(p, c);
  store.current = undefined;
  answered(p, c);
  assert.equal(choose(consult({ question: 'q9', context: full, ccMeetingDelta: delta }), { sessionId: 's3', compactionCount: 0 }).used, false);

  // A restart of the gateway: a new process remembers nothing.
  const fresh = patchedFunctions();
  assert.equal(fresh.ccMeetingContextChoice(consult({ question: 'q', context: full, ccMeetingDelta: delta }), { sessionId: 's2', compactionCount: 2 }).used, false);
});

test('only meeting consults: another surface keeps its args, whatever it carries', () => {
  const { ccMeetingContextChoice: choose, ccMeetingContextRecord: record } = patchedFunctions();
  const store = { current: { sessionId: 's1', compactionCount: 0 } };
  const p = { sessionKey: 'agent:main:subagent:talk:x', args: { question: 'q', context: 'C', ccMeetingDelta: 'D' }, transcript: [], logger: { info: () => {} }, agentRuntime: runtime(store) };
  const c = choose(p, store.current);
  assert.equal(c.meeting, false); assert.equal(c.used, false); assert.equal(c.args.context, 'C');
  record(p, 'main', '/store', c);
  assert.equal(choose(p, store.current).used, false, 'nothing recorded for it');
});
