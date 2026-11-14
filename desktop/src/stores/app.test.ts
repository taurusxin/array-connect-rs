import { beforeEach, describe, expect, it, vi } from "vitest";
import { emptySession, newProfile } from "@/lib/types";

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
});
