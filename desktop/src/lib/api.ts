import { invoke, isTauri } from "@tauri-apps/api/core";
export const native = isTauri();
export async function command<T>(
  name: string,
  args?: Record<string, unknown>,
): Promise<T> {
  if (!native)
    throw new Error("当前为界面预览，请在 Tauri 桌面客户端内使用此功能。");
  return invoke<T>(name, args);
}
