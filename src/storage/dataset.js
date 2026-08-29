export async function writeDatasetObject(bucket, event, { prefix = "events" } = {}) {
  if (!bucket || !event?.event_id) return;

  const safePrefix = String(prefix || "events").replace(/^\/+|\/+$/g, "") || "events";
  const day = event.observed_at.slice(0, 10).replaceAll("-", "/");
  const key = `${safePrefix}/${day}/${event.event_id}.json`;

  await bucket.put(key, JSON.stringify(event), {
    httpMetadata: {
      contentType: "application/json",
    },
  });

  return key;
}
