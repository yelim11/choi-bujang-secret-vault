import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { readAlerts } from './read-alerts.mjs';

const TTL_MS = 15 * 60 * 1000;

const mitreIds = (alert) => {
  const value = alert?.rule?.mitre;
  if (Array.isArray(value)) return value.map(String);
  if (typeof value === 'string') return [value];
  if (Array.isArray(value?.id)) return value.id.map(String);
  if (typeof value?.id === 'string') return [value.id];
  return [];
};

const expiryFor = (timestamp) => {
  const at = Date.parse(timestamp);
  return Number.isFinite(at) ? new Date(at + TTL_MS).toISOString() : null;
};

export function buildDenyRules(alerts, decisions) {
  const byId = new Map(alerts.map((alert) => [alert?.id, alert]));
  const grouped = new Map();

  for (const decision of decisions) {
    if (decision?.action !== 'block' || decision.confidence < 0.85) continue;
    const alert = byId.get(decision.alertId);
    const sourceAddress = alert?.data?.srcip;
    const repeated = Number(alert?.data?.count);
    const t1190 = mitreIds(alert).some((id) => id === 'T1190' || id.startsWith('T1190.'));
    if (!t1190 || typeof sourceAddress !== 'string' || !sourceAddress
        || !Number.isFinite(repeated) || repeated < 2) continue;

    const expiresAt = expiryFor(alert.timestamp);
    if (!expiresAt) continue;

    const current = grouped.get(sourceAddress) ?? {
      ruleId: `xdr.web-injection.deny-${sourceAddress.replaceAll('.', '-')}`,
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
  await writeFile(join(root, 'xdr', 'web-injection', 'deny-rules.json'), `${JSON.stringify({
    schema: 'aleph.xdr.ztna-deny-rules.v1',
    moduleKey: 'web-injection',
    rules,
  }, null, 2)}\n`, 'utf8');

  const logPath = join(root, 'xdr', 'alerts.log');
  const existing = (await readExistingLog(logPath)).split(/\r?\n/u).filter(Boolean);
  const preserved = existing.filter((line) => {
    try { return JSON.parse(line)?.moduleKey !== 'web-injection'; } catch { return true; }
  });

  const current = result.decisions
    .filter((decision) => decision.action === 'block' || decision.action === 'alert')
    .map((decision) => {
      const safe = safeById.get(decision.alertId) ?? {};
      return JSON.stringify({
        moduleKey: 'web-injection',
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
