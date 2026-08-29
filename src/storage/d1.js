export async function insertEvent(db, event) {
  if (!db) return;

  await db
    .prepare(
      `INSERT INTO events (
        event_id,
        installation_id,
        observed_at,
        country,
        asn,
        organization,
        local_risk,
        spoof_signals,
        strong_hardware_spoof,
        local_reasons_json,
        ai1_json,
        ai2_json,
        final_decision,
        final_reasons_json,
        telemetry_summary_json
      ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)`
    )
    .bind(
      event.event_id,
      event.installation_id,
      event.observed_at,
      event.country,
      event.asn,
      event.organization,
      event.local_risk,
      event.spoof_signals,
      event.strong_hardware_spoof ? 1 : 0,
      JSON.stringify(event.local_reasons || []),
      event.ai1 ? JSON.stringify(event.ai1) : null,
      event.ai2 ? JSON.stringify(event.ai2) : null,
      event.final_decision,
      JSON.stringify(event.final_reasons || []),
      JSON.stringify(event.telemetry_summary || {})
    )
    .run();
}
