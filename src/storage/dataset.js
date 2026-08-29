export async function writeDatasetObject(bucket, event) {
  if (!bucket || !event?.event_id) return;

  const day = event.observed_at.slice(0, 10).replaceAll("-", "/");
  const key = `events/${day}/${event.event_id}.json`;

  await bucket.put(key, JSON.stringify(event), {
    httpMetadata: {
      contentType: "application/json",
    },
  });
}
