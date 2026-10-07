import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { readAlerts } from './read-alerts.mjs';

const TTL_MS = 15 * 60 * 1000;

const expiryFor = (timestamp) => {
  const at = Date.parse(timestamp);
  if (!Number.isFinite(at)) return null;
  return new Date(at + TTL_MS).toISOString();
};

export function buildDenyRules(alerts, decisions) {
  const byId = new Map(alerts.map((alert) => [alert?.id, alert]));
  const grouped = new Map();

  for (const decision of decisions) {
    if (decision?.action !== 'block' || decision.confidence < 0.85) continue;
    const alert = byId.get(decision.alertId);
    const mitre = Array.isArray(alert?.rule?.mitre) ? alert.rule.mitre : [];
    const sourceAddress = alert?.data?.srcip;
    if (!mitre.includes('T1110') || typeof sourceAddress !== 'string' || !sourceAddress) continue;

    const expiresAt = expiryFor(alert.timestamp);
    if (!expiresAt) continue;
    const current = grouped.get(sourceAddress) ?? {
      ruleId: `xdr.brute-force.deny-${sourceAddress.replaceAll('.', '-')}`,
      action: 'deny',
      match: { sourceAddress },
      expiresAt,
      evidenceAlertIds: [],
    };
    if (Date.parse(expiresAt) > Date.parse(current.expiresAt)) current.expiresAt = expiresAt;
    current.evidenceAlertIds.push(alert.id);
    grouped.set(sourceAddress, current);
  }

  return [...grouped.values()].map((rule) => ({
    ...rule,
    evidenceAlertIds: [...new Set(rule.evidenceAlertIds)].sort(),
  }));
}

const readExistingLog = async (path) => {
  try { return await readFile(path, 'utf8'); } catch (error) {
    if (error?.code === 'ENOENT') return '';
    throw error;
  }
};

export async function afterRun({ root, fixture, result }) {
  const safeAlerts = await readAlerts(fixture);
  const safeById = new Map(fixture.alerts.map((alert, index) => [alert.id, safeAlerts[index]]));

  const rules = buildDenyRules(fixture.alerts, result.decisions);
  await writeFile(join(root, 'xdr', 'brute-force', 'deny-rules.json'), `${JSON.stringify({
    schema: 'aleph.xdr.ztna-deny-rules.v1',
    moduleKey: 'brute-force',
    rules,
  }, null, 2)}\n`, 'utf8');

  const logPath = join(root, 'xdr', 'alerts.log');
  const existing = (await readExistingLog(logPath)).split(/\r?\n/u).filter(Boolean);
  const preserved = existing.filter((line) => {
    try { return JSON.parse(line)?.moduleKey !== 'brute-force'; } catch { return true; }
  });
  const current = result.decisions
    .filter((decision) => decision.action === 'block' || decision.action === 'alert')
    .map((decision) => {
      const safe = safeById.get(decision.alertId) ?? {};
      return JSON.stringify({
        moduleKey: 'brute-force',
        alertId: decision.alertId,
        action: decision.action,
        confidence: decision.confidence,
        timestamp: safe.timestamp ?? '',
        sourceAddress: safe.sourceAddress ?? '',
        account: safe.account ?? '',
        reason: decision.reason,
      });
    });
  await writeFile(logPath, `${[...preserved, ...current].join('\n')}\n`, 'utf8');
}
