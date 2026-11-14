import { beforeEach, describe, expect, it, vi } from "vitest";
import { emptySession, newProfile, type Preferences } from "@/lib/types";

vi.mock("@/lib/api", () => ({ native: true, command: vi.fn() }));
import { command } from "@/lib/api";
import { useApp } from "./app";

describe("desktop connection and secret boundaries", () => {
  beforeEach(() => {
    vi.mocked(command).mockReset();
    useApp.setState({
      selectedId: "profile",
      busy: false,
      session: emptySession,
      error: null,
      notice: null,
      profiles: [],
      exitState: "idle",
      preferences: { theme: "system", logLevel: "info", closeBehavior: "ask" },
    });
  });
  it("rejects another start while a session is connecting or connected", async () => {
    for (const state of [
      "Connecting",
      "AwaitingPassword",
      "Connected",
      "Reconnecting",
      "Disconnecting",
    ]) {
      useApp.setState({ session: { ...emptySession, state } });
      await useApp.getState().connect();
    }
    expect(command).not.toHaveBeenCalled();
  });
  it("sends secret updates once without retaining them in the global store", async () => {
    const profile = newProfile();
    vi.mocked(command).mockResolvedValue([profile]);
    await useApp.getState().saveProfile(profile, {
      password: "private-test-password",
      totpSecret: "private-test-seed",
      proxyPassword: "private-test-proxy",
    });
    const state = JSON.stringify(useApp.getState());
    expect(state).not.toContain("private-test-");
    expect(command).toHaveBeenCalledWith(
      "save_profile",
      expect.objectContaining({
        secrets: expect.objectContaining({ password: "private-test-password" }),
      }),
    );
  });
  it("keeps an OS autostart failure from displaying a successful setting", async () => {
    useApp.setState({ autostart: false });
    vi.mocked(command).mockRejectedValue(new Error("permission denied"));
    await useApp.getState().setAutostart(true);
    expect(useApp.getState().autostart).toBe(false);
    expect(useApp.getState().error).toBe("permission denied");
  });
  it("keeps the active connection selected when another profile is edited", async () => {
    const profile = newProfile();
    useApp.setState({
      session: {
        ...emptySession,
        state: "Connected",
        profileId: "active-profile",
      },
      selectedId: "active-profile",
    });
    vi.mocked(command).mockResolvedValue([profile]);
    await useApp.getState().saveProfile(profile, {});
    expect(useApp.getState().selectedId).toBe("active-profile");
  });
  it("does not change the selected configuration during an active connection", () => {
    useApp.setState({
      session: {
        ...emptySession,
        state: "Connected",
        profileId: "active-profile",
      },
      selectedId: "active-profile",
    });
    useApp.getState().select("other-profile");
    expect(useApp.getState().selectedId).toBe("active-profile");
  });
  it("serializes preference writes and keeps a later successful choice after an earlier failure", async () => {
    const original = useApp.getState().preferences;
    const first: Preferences = { ...original, closeBehavior: "tray" };
    const second: Preferences = { ...first, closeBehavior: "exit" };
    let rejectFirst!: (error: Error) => void;
    vi.mocked(command)
      .mockImplementationOnce(
        () =>
          new Promise((_, reject) => {
            rejectFirst = reject;
          }),
      )
      .mockResolvedValueOnce(undefined);
    const firstSave = useApp.getState().setPreferences(first);
    const secondSave = useApp.getState().setPreferences(second);
    await Promise.resolve();
    expect(command).toHaveBeenCalledTimes(1);
    rejectFirst(new Error("injected write failure"));
    await Promise.all([firstSave, secondSave]);
    expect(command).toHaveBeenCalledTimes(2);
    expect(useApp.getState().preferences).toEqual(second);
  });
  it("waits for an earlier preference write before remembering the close choice", async () => {
    const original = useApp.getState().preferences;
    const edited: Preferences = { ...original, logLevel: "debug" };
    const remembered: Preferences = { ...edited, closeBehavior: "tray" };
    let finishSave!: () => void;
    vi.mocked(command)
      .mockImplementationOnce(
        () =>
          new Promise<void>((resolve) => {
            finishSave = resolve;
          }),
      )
      .mockResolvedValueOnce(remembered);
    const saving = useApp.getState().setPreferences(edited);
    const choosing = useApp.getState().chooseClose("tray", true);
    await Promise.resolve();
    expect(command).toHaveBeenCalledTimes(1);
    finishSave();
    await saving;
    expect(await choosing).toBe(true);
    expect(command).toHaveBeenLastCalledWith("choose_close", {
      choice: "tray",
      remember: true,
    });
    expect(useApp.getState().preferences).toEqual(remembered);
  });
  it("leaves close preferences unchanged when the user does not remember a choice", async () => {
    const original = useApp.getState().preferences;
    vi.mocked(command).mockResolvedValue(null);
    expect(await useApp.getState().chooseClose("exit", false)).toBe(true);
    expect(useApp.getState().preferences).toEqual(original);
    expect(command).toHaveBeenCalledWith("choose_close", {
      choice: "exit",
      remember: false,
    });
  });
  it("keeps a failed close choice retryable without claiming it was saved", async () => {
    const original = useApp.getState().preferences;
    useApp.setState({ exitState: "choose" });
    vi.mocked(command).mockRejectedValue(new Error("injected save failure"));
    expect(await useApp.getState().chooseClose("tray", true)).toBe(false);
    expect(useApp.getState().preferences).toEqual(original);
    expect(useApp.getState().exitState).toBe("choose");
  });
  it("always sends explicit exit requests to the native connection check", async () => {
    for (const state of [
      "Disconnected",
      "Connecting",
      "Connected",
      "Reconnecting",
    ]) {
      useApp.setState({
        session: { ...emptySession, state },
        preferences: {
          theme: "system",
          logLevel: "info",
          closeBehavior: "tray",
        },
      });
      await useApp.getState().requestExit();
    }
    expect(command).toHaveBeenCalledTimes(4);
    expect(command).toHaveBeenLastCalledWith("request_exit");
  });
  it("does not start a connection while a close or exit dialog is pending", async () => {
    for (const exitState of [
      "choose",
      "checking",
      "confirm",
      "closing",
    ] as const) {
      useApp.setState({ exitState });
      await useApp.getState().connect();
    }
    expect(command).not.toHaveBeenCalled();
  });
});
