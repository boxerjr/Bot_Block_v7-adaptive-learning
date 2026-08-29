export async function getAsnReputation(db, asn) {
  if (!db || !asn) return null;

  return db
    .prepare(
      `SELECT asn, human_count, bot_count, spoof_count, reputation_score, updated_at
       FROM asn_reputation
       WHERE asn = ?1`
    )
    .bind(asn)
    .first();
}
