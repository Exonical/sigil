export type StatusTone = "ok" | "warn" | "danger" | "neutral";

// The tone for the statuses the API reports: tokens, certificates, escrow versions and audit outcomes.
export function statusTone(value: string): StatusTone {
  switch (value) {
    case "active":
    case "success":
      return "ok";
    case "lost":
    case "revoked":
    case "error":
      return "danger";
    case "pending":
    case "unconfirmed":
      return "warn";
    default:
      return "neutral";
  }
}
