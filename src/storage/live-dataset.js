export async function writeLiveLabelObject(bucket, labelRecord) {
  if (!bucket || !labelRecord?.event_id) return null;

  const created = String(labelRecord.created_at || new Date().toISOString());
  const day = created.slice(0, 10).replaceAll("-", "/");
  const key = `labels/${day}/${labelRecord.event_id}.json`;

  await bucket.put(key, JSON.stringify(labelRecord), {
    httpMetadata: {
      contentType: "application/json",
    },
  });

  return key;
}
