import { create } from "zustand";
import { listen } from "@tauri-apps/api/event";
import { command, native } from "@/lib/api";
import {
  emptySession,
  type Bootstrap,
  type CredentialRequest,
  type LiveSession,
  type LogRecord,
  type Preferences,
  type Profile,
  type RatePoint,
  type SecretUpdates,
  type Usage,
} from "@/lib/types";

type Page = "overview" | "profiles" | "logs" | "preferences";
type Store = {
  initialized: boolean;
  page: Page;
  profiles: Profile[];
  selectedId: string | null;
  preferences: Preferences;
  session: LiveSession;
  credentialRequest: CredentialRequest | null;
  logs: LogRecord[];
  samples: RatePoint[];
  usage: Usage;
  autostart: boolean;
  administrator: boolean;
  wintunAvailable: boolean;
  storagePath: string;
  platform: string;
  version: string;
  busy: boolean;
  error: string | null;
  notice: string | null;
  setPage: (page: Page) => void;
  select: (id: string) => void;
  dismiss: () => void;
  initialize: () => Promise<void>;
  refresh: () => Promise<void>;
  refreshUsage: () => Promise<void>;
  saveProfile: (profile: Profile, secrets: SecretUpdates) => Promise<boolean>;
  deleteProfile: (id: string) => Promise<boolean>;
  connect: () => Promise<void>;
  disconnect: () => Promise<void>;
  submit: (password: string, otp: string) => Promise<boolean>;
  setPreferences: (preferences: Preferences) => Promise<void>;
  setAutostart: (enabled: boolean) => Promise<void>;
  clearLogs: () => Promise<void>;
};
let initialization: Promise<void> | null = null;
let sessionRevision = 0;
let credentialRevision = 0;
const message = (error: unknown) =>
  error instanceof Error ? error.message : String(error);

export const useApp = create<Store>((set, get) => ({
  initialized: false,
  page: "overview",
  profiles: [],
  selectedId: null,
  preferences: { theme: "system", logLevel: "info" },
  session: emptySession,
  credentialRequest: null,
  logs: [],
  samples: [],
  usage: {
    bytesSent: 0,
    bytesReceived: 0,
    connectedSeconds: 0,
    sessions: 0,
    recent: [],
  },
  autostart: false,
  administrator: false,
  wintunAvailable: true,
  storagePath: "",
  platform: "",
  version: "0.1.0",
  busy: false,
  error: null,
  notice: null,
  setPage: (page) => set({ page }),
  select: (id) => set({ selectedId: id, page: "overview" }),
  dismiss: () => set({ error: null, notice: null }),
  initialize: () =>
    (initialization ??= (async () => {
      if (!native) {
        set({ initialized: true });
        return;
      }
      try {
        await Promise.all([
          listen<LiveSession>("vpn:session", ({ payload }) => {
            sessionRevision++;
            if (payload.state === "Disconnected") credentialRevision++;
            set((state) => {
              const point = {
                time: Date.now(),
                download: payload.downloadRate,
                upload: payload.uploadRate,
              };
              const samples =
                payload.profileId !== state.session.profileId
                  ? []
                  : state.samples;
              const next =
                samples.length &&
                point.time - samples[samples.length - 1].time < 700
                  ? [...samples.slice(0, -1), point]
                  : [...samples, point];
              return {
                session: payload,
                samples: next.slice(-60),
                credentialRequest:
                  payload.state === "Disconnected"
                    ? null
                    : state.credentialRequest,
              };
            });
          }),
          listen<CredentialRequest>("vpn:credentials", ({ payload }) => {
            credentialRevision++;
            set({ credentialRequest: payload });
          }),
          listen<LogRecord[]>("vpn:logs", ({ payload }) =>
            set((state) => {
              const merged = new Map(
                [...state.logs, ...payload].map((log) => [log.id, log]),
              );
              return {
                logs: [...merged.values()]
                  .sort((a, b) => a.id - b.id)
                  .slice(-2000),
              };
            }),
          ),
          listen("vpn:profiles-changed", () => {
            void get().refresh();
          }),
          listen("vpn:history-changed", () => {
            void get().refreshUsage();
          }),
        ]);
        await get().refresh();
        window.setInterval(() => {
          if (get().session.state !== "Disconnected") void get().refreshUsage();
        }, 5000);
      } catch (error) {
        set({ error: message(error) });
      } finally {
        set({ initialized: true });
      }
    })()),
  refresh: async () => {
    const revision = sessionRevision;
    const credentials = credentialRevision;
    const data = await command<Bootstrap>("bootstrap");
    set((state) => ({
      ...data,
      session: revision === sessionRevision ? data.session : state.session,
      credentialRequest:
        credentials === credentialRevision
          ? data.credentialRequest
          : state.credentialRequest,
      selectedId:
        (revision === sessionRevision ? data.session : state.session).state !==
        "Disconnected"
          ? (revision === sessionRevision ? data.session : state.session)
              .profileId
          : state.selectedId &&
              data.profiles.some((p) => p.id === state.selectedId)
            ? state.selectedId
            : (data.profiles[0]?.id ?? null),
      logs: [
        ...new Map(
          [...data.logs, ...state.logs].map((log) => [log.id, log]),
        ).values(),
      ]
        .sort((a, b) => a.id - b.id)
        .slice(-2000),
    }));
  },
  refreshUsage: async () => {
    try {
      set({ usage: await command<Usage>("usage") });
    } catch (error) {
      set({ error: message(error) });
    }
  },
  saveProfile: async (profile, secrets) => {
    set({ busy: true, error: null });
    try {
      const profiles = await command<Profile[]>("save_profile", {
        profile,
        secrets,
      });
      set((state) => ({
        profiles,
        selectedId:
          state.session.state === "Disconnected"
            ? profile.id
            : state.session.profileId,
        notice: "配置已保存",
      }));
      return true;
    } catch (error) {
      set({ error: message(error) });
      return false;
    } finally {
      set({ busy: false });
    }
  },
  deleteProfile: async (id) => {
    set({ busy: true, error: null });
    try {
      const profiles = await command<Profile[]>("delete_profile", { id });
      set((state) => ({
        profiles,
        selectedId:
          state.selectedId === id
            ? (profiles[0]?.id ?? null)
            : state.selectedId,
        notice: "配置及关联凭据已删除",
      }));
      return true;
    } catch (error) {
      set({ error: message(error) });
      return false;
    } finally {
      set({ busy: false });
    }
  },
  connect: async () => {
    if (
      !get().selectedId ||
      get().session.state !== "Disconnected" ||
      get().busy
    )
      return;
    set({ busy: true, error: null, samples: [] });
    try {
      await command("connect_profile", { id: get().selectedId });
    } catch (error) {
      set({ error: message(error) });
    } finally {
      set({ busy: false });
    }
  },
  disconnect: async () => {
    set({ busy: true, error: null });
    try {
      await command("disconnect");
      set({ credentialRequest: null });
    } catch (error) {
      set({ error: message(error) });
    } finally {
      set({ busy: false });
    }
  },
  submit: async (password, otp) => {
    const request = get().credentialRequest;
    if (!request) return false;
    try {
      await command("submit_credentials", {
        input: { id: request.id, password, otp },
      });
      set({ credentialRequest: null });
      return true;
    } catch (error) {
      set({ error: message(error) });
      return false;
    }
  },
  setPreferences: async (preferences) => {
    const previous = get().preferences;
    set({ preferences });
    try {
      await command("save_preferences", { preferences });
    } catch (error) {
      set({ preferences: previous, error: message(error) });
    }
  },
  setAutostart: async (enabled) => {
    set({ busy: true });
    try {
      set({ autostart: await command<boolean>("set_autostart", { enabled }) });
    } catch (error) {
      set({ error: message(error) });
    } finally {
      set({ busy: false });
    }
  },
  clearLogs: async () => {
    try {
      await command("clear_logs");
      set({ logs: [] });
    } catch (error) {
      set({ error: message(error) });
    }
  },
}));
