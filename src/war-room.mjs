import { randomUUID } from 'node:crypto';
import { RULE_IDS } from './decider.mjs';
import { sameUser } from './device-session.mjs';
import { verifyNoteSnapshot } from './note-backup.mjs';
import { currentPolicy, diffPolicy, verifySnapshot } from './policy-diff.mjs';

const DEVICE_STATES = ['approved', 'pending', 'revoked'];
const safeToken = value => String(value).replace(/\s+/gu, '_').replace(/[^A-Za-z0-9._가-힣-]/gu, '').slice(0, 40);

export const recordOf = summary => ({
  rules: summary.decider.ruleCount,
  detect_status: summary.detect.status,
  detect_events: summary.detect.events === null ? 'not_run' : summary.detect.events,
  revocation_approved: summary.revocation.approved,
  revocation_pending: summary.revocation.pending,
  revocation_revoked: summary.revocation.revoked,
  policy_verified: summary.recovery.policy.verified,
  policy_version: safeToken(summary.recovery.policy.version ?? 'none'),
  policy_changed: summary.recovery.policy.changed ?? 'na',
  notes_verified: summary.recovery.notes.verified,
  notes_version: safeToken(summary.recovery.notes.version ?? 'none'),
  notes_entries: summary.recovery.notes.entries ?? 'na',
});

export const warRoomLogLine = (requestId, record) =>
  `war_room_view request=${requestId} ${Object.entries(record).map(([key,value])=>`${key}=${value}`).join(' ')}`;

function recoveryOf({ policy, notes, config }) {
  const out = {
    status: 'confirmed',
    policy: { verified: false, version: null, shaPrefix: null, changed: null },
    notes: { verified: false, version: null, entries: null },
  };
  try {
    verifySnapshot(policy);
    const diff = diffPolicy(policy, currentPolicy(config));
    out.policy = { verified: true, version: diff.restoreVersion, shaPrefix: diff.sha256.slice(0, 12), changed: diff.changed };
  } catch {}
  try {
    if (verifyNoteSnapshot(notes) === null) out.notes = { verified: true, version: notes.version, entries: notes.notes.length };
  } catch {}
  return out;
}

export function buildWarRoomSummary({ devices, policy, notes, config }) {
  const count = state => devices.filter(row => row.status === state).length;
  return {
    decider: {
      status: 'listed',
      ruleCount: RULE_IDS.length,
      ruleIds: [...RULE_IDS],
      verdicts: { status: 'not_run' },
    },
    detect: {
      status: 'not_run',
      events: null,
      proposals: null,
      note: '탐지 사건 저장소가 이 앱 API에 연결되지 않아 0건으로 추정하지 않습니다.',
    },
    revocation: {
      status: 'confirmed',
      ...Object.fromEntries(DEVICE_STATES.map(state => [state, count(state)])),
    },
    recovery: recoveryOf({ policy, notes, config }),
    totalAssault: {
      status: 'not_run',
      expectedAttackTypes: 41,
      completedAttackTypes: null,
      note: '41종 총공세는 ALEPH 심판 실행 전에는 통과로 표시하지 않습니다.',
    },
  };
}

export async function handleWarRoom({ user, db }, response, {
  policy, notes, config, requestId = randomUUID(), now = new Date(),
}) {
  const { data, error } = await db.from('devices')
    .select('owner_id,status').eq('owner_id', user.userId);
  if (error) return response.status(502).json({ error: 'DB_READ_FAILED' });
  const devices = (data ?? []).filter(row => sameUser(row.owner_id, user));
  const summary = buildWarRoomSummary({ devices, policy, notes, config });
  const logLine = warRoomLogLine(requestId, recordOf(summary));
  try { console.log(logLine); } catch {}
  return response.status(200).json({
    requestId,
    checkedAt: now.toISOString(),
    ...summary,
    logLine,
  });
}
