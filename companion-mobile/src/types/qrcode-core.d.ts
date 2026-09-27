declare module 'qrcode/lib/core/qrcode' {
  interface QrCore {
    create(
      text: string,
      opts?: { errorCorrectionLevel?: 'L' | 'M' | 'Q' | 'H'; version?: number },
    ): { modules: { size: number; data: Uint8Array }; version: number };
  }
  const core: QrCore;
  export default core;
}
