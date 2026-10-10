// Protobuf 64-bit integers arrive as bigint. Zero means "not set" for the timestamp fields.
export function formatUnix(value: bigint | number | undefined): string {
  if (value === undefined || Number(value) === 0) return "—";
  return new Date(Number(value) * 1000).toLocaleString();
}

export function unixSeconds(date: Date): bigint {
  return BigInt(Math.floor(date.getTime() / 1000));
}

export function toDateInput(value: bigint | number | undefined): string {
  if (value === undefined || Number(value) === 0) return "";
  return new Date(Number(value) * 1000).toISOString().slice(0, 10);
}

export function fromDateInput(value: string): bigint {
  if (!value) return 0n;
  return unixSeconds(new Date(`${value}T00:00:00Z`));
}

export function pageCount(total: bigint | number, size: number): number {
  return Math.max(1, Math.ceil(Number(total) / size));
}
