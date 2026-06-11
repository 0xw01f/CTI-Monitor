/**
 * ISO-3166-1 alpha-2 → { name, lat, lng }
 * Flag emoji is derived from the code at runtime.
 */
export interface CountryInfo {
  name: string
  flag: string
  lat: number
  lng: number
}

/** Convert a 2-letter ISO code to a flag emoji */
export function isoToFlag(code: string): string {
  if (!code || code.length !== 2) return '🏳'
  return Array.from(code.toUpperCase())
    .map(c => String.fromCodePoint(0x1f1e6 + c.charCodeAt(0) - 65))
    .join('')
}

/** [name, lat, lng] */
const RAW: Record<string, [string, number, number]> = {
  AF: ['Afghanistan', 33.93, 67.71],
  AL: ['Albania', 41.15, 20.17],
  DZ: ['Algeria', 28.03, 1.66],
  AO: ['Angola', -11.2, 17.87],
  AR: ['Argentina', -38.42, -63.62],
  AM: ['Armenia', 40.07, 45.04],
  AU: ['Australia', -25.27, 133.78],
  AT: ['Austria', 47.52, 14.55],
  AZ: ['Azerbaijan', 40.14, 47.58],
  BH: ['Bahrain', 26.0, 50.55],
  BD: ['Bangladesh', 23.68, 90.36],
  BY: ['Belarus', 53.71, 27.95],
  BE: ['Belgium', 50.50, 4.47],
  BJ: ['Benin', 9.31, 2.32],
  BO: ['Bolivia', -16.29, -63.59],
  BA: ['Bosnia and Herzegovina', 43.92, 17.68],
  BR: ['Brazil', -14.24, -51.93],
  BG: ['Bulgaria', 42.73, 25.49],
  KH: ['Cambodia', 12.57, 104.99],
  CM: ['Cameroon', 3.85, 11.50],
  CA: ['Canada', 56.13, -106.35],
  CL: ['Chile', -35.68, -71.54],
  CN: ['China', 35.86, 104.19],
  CO: ['Colombia', 4.57, -74.30],
  CD: ['Congo (DRC)', -4.04, 21.76],
  CR: ['Costa Rica', 9.75, -83.75],
  HR: ['Croatia', 45.10, 15.20],
  CU: ['Cuba', 21.52, -77.78],
  CY: ['Cyprus', 35.13, 33.43],
  CZ: ['Czech Republic', 49.82, 15.47],
  DK: ['Denmark', 56.26, 9.50],
  DO: ['Dominican Republic', 18.74, -70.16],
  EC: ['Ecuador', -1.83, -78.18],
  EG: ['Egypt', 26.82, 30.80],
  SV: ['El Salvador', 13.79, -88.90],
  EE: ['Estonia', 58.60, 25.01],
  ET: ['Ethiopia', 9.15, 40.49],
  FI: ['Finland', 61.92, 25.75],
  FR: ['France', 46.23, 2.21],
  GE: ['Georgia', 42.32, 43.36],
  DE: ['Germany', 51.17, 10.45],
  GH: ['Ghana', 7.95, -1.02],
  GR: ['Greece', 39.07, 21.82],
  GT: ['Guatemala', 15.78, -90.23],
  HN: ['Honduras', 15.20, -86.24],
  HK: ['Hong Kong', 22.32, 114.17],
  HU: ['Hungary', 47.16, 19.50],
  IN: ['India', 20.59, 78.96],
  ID: ['Indonesia', -0.79, 113.92],
  IR: ['Iran', 32.43, 53.69],
  IQ: ['Iraq', 33.22, 43.68],
  IE: ['Ireland', 53.41, -8.24],
  IL: ['Israel', 31.05, 34.85],
  IT: ['Italy', 41.87, 12.57],
  CI: ["Côte d'Ivoire", 7.54, -5.55],
  JP: ['Japan', 36.20, 138.25],
  JO: ['Jordan', 30.59, 36.24],
  KZ: ['Kazakhstan', 48.02, 66.92],
  KE: ['Kenya', -0.02, 37.91],
  KW: ['Kuwait', 29.31, 47.48],
  KG: ['Kyrgyzstan', 41.20, 74.76],
  LA: ['Laos', 19.86, 102.50],
  LV: ['Latvia', 56.88, 24.60],
  LB: ['Lebanon', 33.85, 35.86],
  LY: ['Libya', 26.34, 17.23],
  LT: ['Lithuania', 55.17, 23.88],
  LU: ['Luxembourg', 49.82, 6.13],
  MY: ['Malaysia', 4.21, 108.46],
  MX: ['Mexico', 23.63, -102.55],
  MD: ['Moldova', 47.41, 28.37],
  MN: ['Mongolia', 46.86, 103.85],
  MA: ['Morocco', 31.79, -7.09],
  MZ: ['Mozambique', -18.67, 35.53],
  MM: ['Myanmar', 16.87, 96.21],
  NP: ['Nepal', 28.39, 84.12],
  NL: ['Netherlands', 52.13, 5.29],
  NZ: ['New Zealand', -40.90, 174.89],
  NI: ['Nicaragua', 12.86, -85.21],
  NG: ['Nigeria', 9.08, 8.68],
  KP: ['North Korea', 40.34, 127.51],
  MK: ['North Macedonia', 41.61, 21.75],
  NO: ['Norway', 60.47, 8.47],
  OM: ['Oman', 21.51, 55.92],
  PK: ['Pakistan', 30.38, 69.35],
  PA: ['Panama', 8.54, -80.78],
  PY: ['Paraguay', -23.44, -58.44],
  PE: ['Peru', -9.19, -75.02],
  PH: ['Philippines', 12.88, 121.77],
  PL: ['Poland', 51.92, 19.14],
  PT: ['Portugal', 39.40, -8.22],
  PR: ['Puerto Rico', 18.22, -66.59],
  QA: ['Qatar', 25.35, 51.18],
  RO: ['Romania', 45.94, 24.97],
  RU: ['Russia', 61.52, 105.32],
  SA: ['Saudi Arabia', 23.89, 45.08],
  SN: ['Senegal', 14.50, -14.45],
  RS: ['Serbia', 44.02, 21.01],
  SG: ['Singapore', 1.35, 103.82],
  SK: ['Slovakia', 48.67, 19.70],
  SI: ['Slovenia', 46.15, 14.99],
  SO: ['Somalia', 5.15, 46.20],
  ZA: ['South Africa', -30.56, 22.94],
  KR: ['South Korea', 35.91, 127.77],
  SS: ['South Sudan', 7.86, 29.69],
  ES: ['Spain', 40.46, -3.75],
  LK: ['Sri Lanka', 7.87, 80.77],
  SD: ['Sudan', 12.86, 30.22],
  SE: ['Sweden', 60.13, 18.64],
  CH: ['Switzerland', 46.82, 8.23],
  SY: ['Syria', 34.80, 38.99],
  TW: ['Taiwan', 23.70, 120.96],
  TJ: ['Tajikistan', 38.86, 71.28],
  TZ: ['Tanzania', -6.37, 34.89],
  TH: ['Thailand', 15.87, 100.99],
  TN: ['Tunisia', 33.89, 9.54],
  TR: ['Turkey', 38.96, 35.24],
  TM: ['Turkmenistan', 38.97, 59.56],
  UG: ['Uganda', 1.37, 32.29],
  UA: ['Ukraine', 48.38, 31.17],
  AE: ['United Arab Emirates', 23.42, 53.85],
  GB: ['United Kingdom', 55.38, -3.44],
  US: ['United States', 37.09, -95.71],
  UY: ['Uruguay', -32.52, -55.77],
  UZ: ['Uzbekistan', 41.38, 64.59],
  VE: ['Venezuela', 6.42, -66.59],
  VN: ['Vietnam', 14.06, 108.28],
  YE: ['Yemen', 15.55, 48.52],
  ZM: ['Zambia', -13.13, 27.85],
  ZW: ['Zimbabwe', -19.02, 29.15],
}

export function getCountryInfo(code: string): CountryInfo | null {
  if (!code) return null
  const entry = RAW[code.toUpperCase()]
  if (!entry) return null
  return { name: entry[0], flag: isoToFlag(code), lat: entry[1], lng: entry[2] }
}

/** Render ISO code as "🇨🇳 China" — falls back to raw code if unknown */
export function countryLabel(code: string | null | undefined): string {
  if (!code) return 'Unknown'
  const info = getCountryInfo(code)
  if (!info) return code
  return `${info.flag} ${info.name}`
}
