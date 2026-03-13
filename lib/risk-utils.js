// ============================================================
// 🧠 lib/risk-utils.js — Behavioral Risk Scoring Helper
//
// ใช้โดย:
//   api/assess.js       → mergeScores(ruleScore, behaviorScore) ก่อน login
//   api/session-risk.js → mergeScores(preScore, postScore, weights) หลัง login
//
// Fail strategy: engine down → คืน null → caller ใช้ fallback score เอง
// ============================================================

const RISK_ENGINE_URL        = process.env.RISK_ENGINE_URL;
const RISK_API_SECRET        = process.env.RISK_API_SECRET;
const RISK_ENGINE_TIMEOUT_MS = 3000;

// ── Behavior payload validator ────────────────────────────────
function isValidBehavior(b) {
    if (!b || typeof b !== 'object') return false;
    const statsOk = (s) =>
        s && typeof s === 'object' &&
        typeof s.m === 'number' && s.m >= 0 && s.m <= 1 &&
        typeof s.s === 'number' && s.s >= 0 && s.s <= 1;
    const featOk  = (f) =>
        f && typeof f === 'object' &&
        typeof f.density    === 'number' && f.density    >= 0 && f.density    <= 1 &&
        typeof f.idle_ratio === 'number' && f.idle_ratio >= 0 && f.idle_ratio <= 1;
    return statsOk(b.mouse) && statsOk(b.click) &&
           statsOk(b.key)   && statsOk(b.idle)  && featOk(b.features);
}

// ── แปลง IF raw_score → [0, 1] ───────────────────────────────
// IsolationForest.score_samples():
//   ใกล้  0.0  = anomalous มาก  → score สูง = เสี่ยง
//   ใกล้ -0.5  = normal มาก    → score ต่ำ = ปลอดภัย
// ค่าจาก model จริง (isolation_forest_model.pkl)
// offset_  = decision boundary ของ IF — score >= offset → normal, < offset → anomaly
// SCORE_MOST_ANOMALOUS = empirical min จาก 10,000 random samples
const SCORE_OFFSET        = -0.5000;  // model.offset_
const SCORE_MOST_ANOMALOUS = -0.7330;  // empirical min

export function rawScoreToBehaviorScore(rawScore) {
    // Offset-based normalization ใช้ model.offset_ เป็น anchor:
    //   score >= offset → normal → 0.0 (ไม่มี risk)
    //   score <  offset → anomalous → map [offset → most_anomalous] เป็น [0.0 → 1.0]
    if (rawScore >= SCORE_OFFSET) return 0.0;
    return Math.min(1.0, (SCORE_OFFSET - rawScore) / (SCORE_OFFSET - SCORE_MOST_ANOMALOUS));
}

// ── เรียก Risk Engine ─────────────────────────────────────────
export async function fetchBehaviorScore(behavior) {
    if (!RISK_ENGINE_URL || !RISK_API_SECRET) return null;
    if (!isValidBehavior(behavior)) return null;

    const controller = new AbortController();
    const timeout    = setTimeout(() => controller.abort(), RISK_ENGINE_TIMEOUT_MS);
    try {
        const res = await fetch(`${RISK_ENGINE_URL}/score`, {
            method:  'POST',
            headers: {
                'Content-Type': 'application/json',
                'x-api-key':    RISK_API_SECRET,
            },
            body:   JSON.stringify(behavior),
            signal: controller.signal,
        });
        if (!res.ok) {
            console.error(`[WARN] risk-utils: engine returned ${res.status}`);
            return null;
        }
        const data = await res.json();
        if (typeof data.raw_score !== 'number') return null;
        return rawScoreToBehaviorScore(data.raw_score);
    } catch (err) {
        if (err.name === 'AbortError') console.error('[WARN] risk-utils: engine timeout');
        else console.error('[WARN] risk-utils: engine error:', err.message);
        return null;
    } finally {
        clearTimeout(timeout);
    }
}

// ── mergeScores ───────────────────────────────────────────────
// กรณี 1 — assess.js (pre-login):
//   mergeScores(ruleScore, behaviorScore)
//   default weight: A=0.6, B=0.4
//   behaviorScore = null → คืน ruleScore เดิม
//
// กรณี 2 — session-risk.js (post-login):
//   mergeScores(preScore, postScore, { preWeight: 0.3, postWeight: 0.7 })
//   postScore = null → คืน preScore (conservative fallback)
//
// safety floor: ผล merge ต้องไม่ต่ำกว่า scoreA × 0.9
export function mergeScores(scoreA, scoreB, options = {}) {
    const { preWeight = 0.6, postWeight = 0.4 } = options;
    if (scoreB === null || scoreB === undefined) return scoreA;
    const weighted = scoreA * preWeight + scoreB * postWeight;
    return Math.max(weighted, scoreA * 0.9);
}
