/** applies one key to a decimal amount string (at most `decimals` fraction digits, no leading zeros) */
export function applyKey(value: string, key: string, decimals: number): string {
  if (key === 'del') return value.length <= 1 ? '0' : value.slice(0, -1);
  if (key === '.') return decimals === 0 || value.includes('.') ? value : `${value}.`;
  const [, frac] = value.split('.');
  if (frac !== undefined && frac.length >= Math.min(decimals, 8)) return value;
  if (value.replace('.', '').length >= 16) return value;
  return value === '0' ? key : value + key;
}
