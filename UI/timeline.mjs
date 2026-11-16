// Preserve each summary's identity so expanded locations follow it across tabs.
export function activityTimeline(app) {
  return [
    ...app.activity.map((record, i) => ({ id: `e${i}`, type: record.group, record })),
    ...app.endpoints.map((record, i) => ({ id: `n${i}`, type: 'network', record }))
  ].sort((a, b) => b.record.last - a.record.last || b.record.first - a.record.first || a.id.localeCompare(b.id));
}
