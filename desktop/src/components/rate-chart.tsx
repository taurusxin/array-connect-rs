import { useId, useState, type PointerEvent } from "react";
import { ArrowDown, ArrowUp, Activity } from "lucide-react";
import { bytes } from "@/lib/format";
import type { RatePoint } from "@/lib/types";

export function RateChart({
  samples,
  download,
  upload,
  connected,
}: {
  samples: RatePoint[];
  download: number;
  upload: number;
  connected: boolean;
}) {
  const tooltipId = useId();
  const [hoverPosition, setHoverPosition] = useState<number | null>(null);
  const hoveredIndex =
    hoverPosition === null
      ? -1
      : Math.round(hoverPosition * 59) - (60 - samples.length);
  const hovered = samples[hoveredIndex];
  const x = (index: number) => ((index + 60 - samples.length) / 59) * 800;
  const maximum =
    Math.max(1024, ...samples.flatMap((s) => [s.download, s.upload])) * 1.2;
  const y = (value: number) => 145 - (value / maximum) * 125;
  const hover = (event: PointerEvent<HTMLDivElement>) => {
    const bounds = event.currentTarget.getBoundingClientRect();
    setHoverPosition(
      bounds.width > 0
        ? Math.max(0, Math.min(1, (event.clientX - bounds.left) / bounds.width))
        : null,
    );
  };
  const path = (key: "download" | "upload") =>
    samples
      .map(
        (sample, index) =>
          `${index ? "L" : "M"}${x(index).toFixed(1)},${y(sample[key]).toFixed(1)}`,
      )
      .join(" ");
  return (
    <section className="panel rate-panel">
      <div className="panel-heading">
        <div>
          <h2>实时网络活动</h2>
          <p>最近 60 秒 · 每秒更新</p>
        </div>
        <span className="subtle-label">
          <span className={connected ? "status-dot connected" : "status-dot"} />
          {connected ? "实时" : "等待连接"}
        </span>
      </div>
      <div className="rate-values">
        <div>
          <span className="rate-label">
            <ArrowDown size={13} />
            下载速度
          </span>
          <strong>
            {bytes(download)}
            <small>/s</small>
          </strong>
        </div>
        <div>
          <span className="rate-label upload">
            <ArrowUp size={13} />
            上传速度
          </span>
          <strong>
            {bytes(upload)}
            <small>/s</small>
          </strong>
        </div>
      </div>
      <div className="chart">
        <div className="chart-axis">
          <span>{bytes(maximum)}</span>
          <span>{bytes(maximum / 2)}</span>
          <span>0 B/s</span>
        </div>
        <div className="chart-surface">
          <div
            className="chart-plot"
            onPointerEnter={hover}
            onPointerMove={hover}
            onPointerLeave={() => setHoverPosition(null)}
            onPointerCancel={() => setHoverPosition(null)}
          >
            <svg
              viewBox="0 0 800 155"
              preserveAspectRatio="none"
              role="img"
              aria-label="最近六十秒的上传与下载速度"
              aria-describedby={hovered ? tooltipId : undefined}
            >
              <defs>
                <linearGradient id="download-fill" x1="0" y1="0" x2="0" y2="1">
                  <stop
                    offset="0%"
                    stopColor="var(--chart-download)"
                    stopOpacity=".15"
                  />
                  <stop
                    offset="100%"
                    stopColor="var(--chart-download)"
                    stopOpacity="0"
                  />
                </linearGradient>
              </defs>
              {[20, 80, 145].map((y) => (
                <line
                  key={y}
                  x1="0"
                  x2="800"
                  y1={y}
                  y2={y}
                  stroke="var(--border)"
                  strokeDasharray="3 5"
                />
              ))}
              {samples.length > 1 && (
                <>
                  <path
                    d={`${path("download")} L800,155 L${x(0).toFixed(1)},155 Z`}
                    fill="url(#download-fill)"
                  />
                  <path
                    d={path("download")}
                    fill="none"
                    stroke="var(--chart-download)"
                    strokeWidth="2"
                    vectorEffect="non-scaling-stroke"
                  />
                  <path
                    d={path("upload")}
                    fill="none"
                    stroke="var(--chart-upload)"
                    strokeWidth="2"
                    vectorEffect="non-scaling-stroke"
                  />
                </>
              )}
              {hovered && (
                <g aria-hidden="true" pointerEvents="none">
                  <line
                    x1={x(hoveredIndex)}
                    x2={x(hoveredIndex)}
                    y1="0"
                    y2="145"
                    stroke="var(--muted-foreground)"
                    strokeDasharray="3 4"
                    vectorEffect="non-scaling-stroke"
                  />
                  {(["download", "upload"] as const).map((key) => (
                    <circle
                      key={key}
                      cx={x(hoveredIndex)}
                      cy={y(hovered[key])}
                      r="3.5"
                      fill={`var(--chart-${key})`}
                      stroke="var(--card)"
                      strokeWidth="1.5"
                      vectorEffect="non-scaling-stroke"
                    />
                  ))}
                </g>
              )}
            </svg>
            {!samples.some((s) => s.download || s.upload) && (
              <div className="chart-empty">
                <Activity size={17} />
                {connected
                  ? "连接已建立，等待网络活动"
                  : "连接后在这里查看实时网速"}
              </div>
            )}
            {hovered && (
              <div
                id={tooltipId}
                role="tooltip"
                className="chart-tooltip"
                style={{
                  left: `clamp(8px, calc(${(x(hoveredIndex) / 800) * 100}% + 12px), calc(100% - 188px))`,
                }}
              >
                <time dateTime={new Date(hovered.time).toISOString()}>
                  {new Date(hovered.time).toLocaleTimeString("zh-CN", {
                    hour: "2-digit",
                    minute: "2-digit",
                    second: "2-digit",
                    hourCycle: "h23",
                  })}
                </time>
                <div className="chart-tooltip-row">
                  <span className="rate-label">
                    <ArrowDown size={12} />
                    下载
                  </span>
                  <strong>{bytes(hovered.download)}/s</strong>
                </div>
                <div className="chart-tooltip-row">
                  <span className="rate-label upload">
                    <ArrowUp size={12} />
                    上传
                  </span>
                  <strong>{bytes(hovered.upload)}/s</strong>
                </div>
              </div>
            )}
          </div>
          <div className="chart-time">
            <span>60 秒前</span>
            <span>30 秒前</span>
            <span>现在</span>
          </div>
        </div>
      </div>
      <div className="chart-legend">
        <span>
          <i />
          下载
        </span>
        <span>
          <i className="upload" />
          上传
        </span>
      </div>
    </section>
  );
}
