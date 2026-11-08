export type LicenseState = {
  mode: "licensed" | "trial" | "trial_expired" | "license_expired" | "revoked" | "invalid";
  message: string;
  features: string[];
  license_id?: string;
  serial?: number;
  customer?: string;
  edition?: string;
  max_clients: number;
  expires_at?: string;
  trial_ends_at: string;
  days_left: number;
  hardware_id: string;
  effective_time: string;
  clock_rollback: boolean;
  tamper_events: { kind: string; detail: string; detected_at: string }[];
  revocation?: { license_id: string; reason: string; at: string };
  last_sync?: { at: string; ok: boolean; status?: string; message: string };
  trusted_key_ids: string[];
};

export const MODE_LABEL: Record<LicenseState["mode"], [string, "ok" | "warn" | "bad"]> = {
  licensed: ["Licensed", "ok"],
  trial: ["Trial", "warn"],
  trial_expired: ["Trial ended", "bad"],
  license_expired: ["License expired", "bad"],
  revoked: ["Revoked", "bad"],
  invalid: ["Invalid license", "bad"],
};
