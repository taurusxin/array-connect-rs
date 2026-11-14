export function bytes(value: number, decimals = 1): string {
  const safe = Number.isFinite(value) ? Math.max(value, 0) : 0;
  if (safe < 1024) return `${Math.round(safe)} B`;
  const unit = Math.min(Math.floor(Math.log(safe) / Math.log(1024)), 4);
  return `${(safe / 1024 ** unit).toFixed(decimals)} ${["B", "KiB", "MiB", "GiB", "TiB"][unit]}`;
}
export function duration(seconds: number): string {
  const value = Math.max(0, Math.floor(seconds));
  return [Math.floor(value / 3600), Math.floor(value / 60) % 60, value % 60]
    .map((n) => String(n).padStart(2, "0"))
    .join(":");
}
export function host(server: string): string {
  try {
    return new URL(server.includes("://") ? server : `https://${server}`).host;
  } catch {
    return server || "尚未设置网关";
  }
}
export function date(timestamp: number): string {
  return new Intl.DateTimeFormat("zh-CN", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  }).format(timestamp);
}
