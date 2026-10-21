/**
 * The dashboard's own availability topic lives outside the per-unit namespace
 * (`status/{id}`), so no Spark id — "dashboard" included — can collide with it.
 */
export function dashboardStatusTopic(prefix) {
  return `${prefix}/dashboard/status`;
}
