// Dev-only fixture data for VITE_MOCK_API=1. This module is only imported when that flag is set at build or serve
// time, so production bundles do not contain it. Values are invented; no real serials, users or secrets appear here.

const T = (n: number) => BigInt(1_790_000_000 + n);

export const mockUser = { id: "u-admin1", username: "admin1", email: "admin1@example.test", displayName: "Sigil Admin" };

export const mockTokens = [
  {
    id: "t-1",
    vendor: "Yubico",
    model: "YubiKey 5C NFC FIPS",
    serial: "39192733",
    firmware: "5.7.4",
    formFactor: "Keychain (USB-C)",
    nickname: "front desk",
    status: "active",
    assignedUser: mockUser,
    lostAtUnix: 0n,
    lastSeenUnix: T(600),
    activeCertificates: 1n,
  },
  {
    id: "t-2",
    vendor: "Yubico",
    model: "YubiKey 5 NFC",
    serial: "40000001",
    firmware: "5.4.3",
    formFactor: "Keychain (USB-A)",
    nickname: "",
    status: "unassigned",
    assignedUser: undefined,
    lostAtUnix: 0n,
    lastSeenUnix: T(120),
    activeCertificates: 0n,
  },
  {
    id: "t-3",
    vendor: "Yubico",
    model: "YubiKey 5C",
    serial: "40000002",
    firmware: "5.2.7",
    formFactor: "Keychain (USB-C)",
    nickname: "night shift",
    status: "lost",
    assignedUser: { id: "u-2", username: "jsmith", email: "jsmith@example.test", displayName: "J. Smith" },
    lostAtUnix: T(-3600),
    lastSeenUnix: T(-4000),
    activeCertificates: 1n,
  },
  {
    id: "t-4",
    vendor: "Yubico",
    model: "YubiKey 5 Nano",
    serial: "40000003",
    firmware: "5.4.3",
    formFactor: "Nano (USB-A)",
    nickname: "",
    status: "retired",
    assignedUser: undefined,
    lostAtUnix: 0n,
    lastSeenUnix: T(-90000),
    activeCertificates: 0n,
  },
];

const certificates = [
  {
    id: "c-1",
    tokenSerial: "39192733",
    slot: "9a",
    profile: "piv-authentication",
    userDisplay: "admin1",
    serialNumber: "5e1a7c02",
    attestation: { present: true, attestedSerial: "39192733", firmware: "5.7.4", slot: "9a", pinPolicy: "02", touchPolicy: "01", root: "Yubico Attestation Root 1" },
    subject: "CN=admin1",
    notBeforeUnix: T(-86400),
    notAfterUnix: T(86400 * 30),
    status: "active",
    revokedAtUnix: 0n,
    revocationReason: "",
  },
  {
    id: "c-2",
    tokenSerial: "39192733",
    slot: "9a",
    profile: "piv-authentication",
    userDisplay: "admin1",
    serialNumber: "4c0b9d11",
    subject: "CN=admin1",
    notBeforeUnix: T(-86400 * 60),
    notAfterUnix: T(-86400 * 30),
    status: "superseded",
    revokedAtUnix: 0n,
    revocationReason: "",
  },
  {
    id: "c-3",
    tokenSerial: "40000002",
    slot: "9a",
    profile: "piv-authentication",
    userDisplay: "jsmith",
    serialNumber: "7a22f0e4",
    subject: "CN=jsmith",
    notBeforeUnix: T(-86400 * 10),
    notAfterUnix: T(86400 * 2),
    status: "active",
    revokedAtUnix: 0n,
    revocationReason: "",
  },
];

const escrow = [
  { kind: "puk", version: 2, state: "active", createdAtUnix: T(-86400 * 20), activatedAtUnix: T(-86400 * 20 + 60) },
  { kind: "puk", version: 1, state: "superseded", createdAtUnix: T(-86400 * 90), activatedAtUnix: T(-86400 * 90 + 60) },
  { kind: "management_key", version: 1, state: "active", createdAtUnix: T(-86400 * 20), activatedAtUnix: T(-86400 * 20 + 60) },
];

const audit = [
  { seq: 1042n, occurredAtUnix: T(-300), actorType: "user", actorId: "admin1", action: "Admin.GetToken", targetType: "token", targetId: "39192733", outcome: "success", detailJson: "{\"vendor\":\"Yubico\"}" },
  { seq: 1041n, occurredAtUnix: T(-900), actorType: "user", actorId: "admin1", action: "IssueCertificate", targetType: "token", targetId: "39192733", outcome: "success", detailJson: "{\"profile\":\"piv-authentication\",\"slot\":\"9a\"}" },
  { seq: 1040n, occurredAtUnix: T(-2400), actorType: "user", actorId: "helpdesk1", action: "ReportLost", targetType: "token", targetId: "40000002", outcome: "success", detailJson: "{}" },
  { seq: 1039n, occurredAtUnix: T(-3600), actorType: "system", actorId: "lost-key-job", action: "RevokeCertificate", targetType: "certificate", targetId: "c-3", outcome: "error", detailJson: "{\"error\":\"step-ca unavailable\"}" },
  { seq: 1038n, occurredAtUnix: T(-7200), actorType: "user", actorId: "admin1", action: "SetNickname", targetType: "token", targetId: "39192733", outcome: "success", detailJson: "{\"nickname\":\"front desk\"}" },
];

export const mockData = {
  dashboard: {
    tokensByStatus: { active: 1n, unassigned: 1n, lost: 1n, retired: 1n },
    activeCertificates: 2n,
    certificatesExpiring30Days: 2n,
    stationsByStatus: { active: 2n, disabled: 0n },
    lostTokensPendingRevocation: 1n,
  },
  tokens: mockTokens,
  tokenDetail: (serial: string) => {
    const token = mockTokens.find((item) => item.serial === serial);
    if (!token) return undefined;
    return {
      token,
      certificates: certificates.filter((item) => item.tokenSerial === token.serial),
      escrow,
      audit: audit.filter((item) => item.targetId === token.serial || item.targetId === token.id),
    };
  },
  certificates,
  stations: [
    { id: "station-front", dnsName: "front-desk-01.corp.example", displayName: "Front desk 01", mode: "station", status: "active" },
    { id: "station-hr", dnsName: "hr-02.corp.example", displayName: "HR 02", mode: "station", status: "active" },
  ],
  users: [
    { user: mockUser, tokenCount: 1n },
    { user: { id: "u-2", username: "jsmith", email: "jsmith@example.test", displayName: "J. Smith" }, tokenCount: 1n },
    { user: { id: "u-3", username: "rlee", email: "rlee@example.test", displayName: "R. Lee" }, tokenCount: 0n },
  ],
  audit,
};
