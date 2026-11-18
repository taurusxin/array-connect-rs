import { create } from "zustand";
import { listen } from "@tauri-apps/api/event";
import { command, native } from "@/lib/api";
import {
  emptySession,
  type Bootstrap,
  type CloseChoice,
  type CredentialRequest,
  type ExitState,
  type LiveSession,
  type LogRecord,
  type NetworkServiceStatus,
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
  autostartError: string | null;
  trayAvailable: boolean;
  exitState: ExitState;
  administrator: boolean;
  networkService: NetworkServiceStatus | null;
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
  enrollOtp: (
    id: string,
    password: string,
    confirmOverwrite: boolean,
  ) => Promise<Profile | null>;
  deleteProfile: (id: string) => Promise<boolean>;
  connect: () => Promise<void>;
  disconnect: () => Promise<void>;
  submit: (password: string, otp: string) => Promise<boolean>;
  setPreferences: (preferences: Preferences) => Promise<void>;
  setAutostart: (enabled: boolean) => Promise<void>;
  refreshNetworkService: () => Promise<void>;
  installNetworkService: () => Promise<boolean>;
  clearLogs: () => Promise<void>;
  requestExit: () => Promise<void>;
  chooseClose: (choice: CloseChoice, remember: boolean) => Promise<boolean>;
  confirmExit: () => Promise<void>;
  cancelExit: () => Promise<void>;
};
let initialization: Promise<void> | null = null;
let sessionRevision = 0;
let credentialRevision = 0;
let networkServiceRevision = 0;
let exitRevision = 0;
let preferenceRevision = 0;
let preferencePending = 0;
let preferenceQueue = Promise.resolve();
let confirmedPreferences: Preferences;
const message = (error: unknown) =>
  error instanceof Error ? error.message : String(error);

export const useApp = create<Store>((set, get) => ({
  initialized: false,
  page: "overview",
  profiles: [],
  selectedId: null,
  preferences: {
    theme: "system",
    logLevel: "info",
    closeBehavior: "ask",
  },
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
  autostartError: null,
  trayAvailable: false,
  exitState: "idle",
  administrator: false,
  networkService: null,
  wintunAvailable: true,
  storagePath: "",
  platform: "",
  version: "0.5.1",
  busy: false,
  error: null,
  notice: null,
  setPage: (page) => set({ page }),
  select: (id) => {
    if (
      get().session.state !== "Disconnected" &&
      get().session.profileId !== id
    )
      return;
    set({ selectedId: id, page: "overview" });
  },
  dismiss: () => set({ error: null, notice: null }),
  initialize: () =>
    (initialization ??= (async () => {
      if (!native) {
        set({ initialized: true });
        return;
      }
      try {
        await Promise.all([
          listen<ExitState>("app:exit-state", ({ payload }) => {
            exitRevision++;
            set({ exitState: payload });
          }),
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
    const exit = exitRevision;
    const preference = preferenceRevision;
    const preferenceWasPending = preferencePending > 0;
    const data = await command<Bootstrap>("bootstrap");
    set((state) => ({
      ...data,
      exitState: exit === exitRevision ? data.exitState : state.exitState,
      preferences:
        preferenceWasPending ||
        preferencePending > 0 ||
        preference !== preferenceRevision
          ? state.preferences
          : data.preferences,
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
  enrollOtp: async (id, password, confirmOverwrite) => {
    if (
      !confirmOverwrite ||
      get().busy ||
      get().exitState !== "idle" ||
      get().session.state !== "Disconnected"
    ) {
      set({
        error: !confirmOverwrite
          ? "请先确认覆盖已有 OTP 注册"
          : "请先等待当前连接或操作结束",
      });
      return null;
    }
    set({ busy: true, error: null });
    try {
      const profile = await command<Profile>("enroll_otp", {
        input: { id, password, confirmOverwrite },
      });
      set((state) => ({
        profiles: state.profiles.map((old) => (old.id === id ? profile : old)),
        notice: "OTP 注册成功，密钥已保存到系统密钥库",
      }));
      return profile;
    } catch (error) {
      set({ error: message(error) });
      return null;
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
      get().exitState !== "idle" ||
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
    if (get().error) await get().refreshNetworkService();
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
    if (preferencePending === 0) confirmedPreferences = get().preferences;
    preferencePending++;
    const revision = ++preferenceRevision;
    set({ preferences });
    const operation = preferenceQueue.then(() =>
      command<void>("save_preferences", { preferences }),
    );
    preferenceQueue = operation.catch(() => {});
    try {
      await operation;
      confirmedPreferences = preferences;
    } catch (error) {
      set({
        ...(revision === preferenceRevision
          ? { preferences: confirmedPreferences }
          : {}),
        error: message(error),
      });
    } finally {
      preferencePending--;
    }
  },
  setAutostart: async (enabled) => {
    set({ busy: true });
    try {
      set({
        autostart: await command<boolean>("set_autostart", { enabled }),
        autostartError: null,
      });
    } catch (error) {
      set({ error: message(error) });
    } finally {
      set({ busy: false });
    }
  },
  refreshNetworkService: async () => {
    if (get().platform !== "macos" || get().busy) return;
    const revision = ++networkServiceRevision;
    try {
      const networkService = await command<NetworkServiceStatus>(
        "network_service_status",
      );
      if (revision === networkServiceRevision) set({ networkService });
    } catch (error) {
      if (revision === networkServiceRevision) set({ error: message(error) });
    }
  },
  installNetworkService: async () => {
    const { busy, networkService } = get();
    if (
      busy ||
      !networkService ||
      networkService === "enabled" ||
      networkService === "unavailable"
    )
      return false;
    networkServiceRevision++;
    set({ busy: true, error: null });
    try {
      set({
        networkService: await command<NetworkServiceStatus>(
          "install_network_service",
        ),
      });
      return true;
    } catch (error) {
      set({ error: message(error) });
      return false;
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
  requestExit: async () => {
    try {
      await command("request_exit");
    } catch (error) {
      set({ error: message(error) });
    }
  },
  chooseClose: async (choice, remember) => {
    // Share the preference queue so an earlier save cannot overwrite this choice.
    if (preferencePending === 0) confirmedPreferences = get().preferences;
    preferencePending++;
    const revision = ++preferenceRevision;
    const operation = preferenceQueue.then(() =>
      command<Preferences | null>("choose_close", { choice, remember }),
    );
    preferenceQueue = operation.then(
      () => {},
      () => {},
    );
    try {
      const preferences = await operation;
      if (preferences) {
        confirmedPreferences = preferences;
        if (revision === preferenceRevision) set({ preferences });
      }
      return true;
    } catch (error) {
      set({ error: message(error) });
      return false;
    } finally {
      preferencePending--;
    }
  },
  confirmExit: async () => {
    try {
      await command("confirm_exit");
    } catch (error) {
      set({ error: message(error) });
    }
  },
  cancelExit: async () => {
    try {
      await command("cancel_exit");
    } catch (error) {
      set({ error: message(error) });
    }
  },
}));
