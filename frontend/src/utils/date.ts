// Tarih/saat biçimlendirme yardımcıları (Türkiye biçimi: Gün/Ay/Yıl, 24 saat, AM/PM yok)

const pad = (n: number) => String(n).padStart(2, '0');

/**
 * Tam tarih ve saat: "05/06/2026, 11:17:42"
 */
export function formatDateTime(value: string | number | Date): string {
  const d = new Date(value);
  if (isNaN(d.getTime())) return '';
  return (
    `${pad(d.getDate())}/${pad(d.getMonth() + 1)}/${d.getFullYear()}, ` +
    `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
  );
}

/**
 * Sadece tarih: "05/06/2026"
 */
export function formatDate(value: string | number | Date): string {
  const d = new Date(value);
  if (isNaN(d.getTime())) return '';
  return `${pad(d.getDate())}/${pad(d.getMonth() + 1)}/${d.getFullYear()}`;
}
