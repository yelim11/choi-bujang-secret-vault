let reviewer = null;

export function configureJev(nextReviewer) {
  if (nextReviewer !== null && typeof nextReviewer !== 'function') {
    throw new TypeError('invalid_jev_reviewer');
  }
  reviewer = nextReviewer;
}

export async function askJev(input, { timeoutMs = 250 } = {}) {
  if (!reviewer) return null;

  let timer;
  try {
    const answer = await Promise.race([
      Promise.resolve().then(() => reviewer(input)),
      new Promise((resolve) => {
        timer = setTimeout(() => resolve(null), timeoutMs);
        timer.unref?.();
      }),
    ]);
    const confidence = typeof answer === 'number' ? answer : answer?.confidence;
    if (typeof confidence !== 'number' || !Number.isFinite(confidence)
        || confidence < 0 || confidence > 1) return null;
    return confidence;
  } catch {
    return null;
  } finally {
    if (timer) clearTimeout(timer);
  }
}
