// Encodes DER bytes as a PEM CERTIFICATE block, 64 characters per line, with a trailing newline.
export function derToPem(der: Uint8Array): string {
  let binary = "";
  for (const byte of der) binary += String.fromCharCode(byte);
  const base64 = btoa(binary);
  const lines = base64.match(/.{1,64}/g) ?? [];
  return `-----BEGIN CERTIFICATE-----\n${lines.join("\n")}\n-----END CERTIFICATE-----\n`;
}

// Starts a client-side download of text. The file is generated in the browser; nothing is sent to the server.
export function downloadText(filename: string, text: string): void {
  const url = URL.createObjectURL(new Blob([text], { type: "application/x-pem-file" }));
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}
