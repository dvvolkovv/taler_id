export interface BillingPackage {
  id: 'starter' | 'pro' | 'business';
  amountPlanck: bigint;
  priceEurCents: number; // display-only stub
  label: { ru: string; en: string };
  highlights: { ru: string[]; en: string[] };
}

export const PACKAGES: BillingPackage[] = [
  {
    id: 'starter',
    amountPlanck: 430_000_000n,
    priceEurCents: 464,
    label: { ru: 'Starter', en: 'Starter' },
    highlights: {
      ru: ['~17 мин ассистента', '~500 веб-поисков', '~12 мин обзвона'],
      en: ['~17 min assistant', '~500 web searches', '~12 min outbound'],
    },
  },
  {
    id: 'pro',
    amountPlanck: 2_140_000_000n,
    priceEurCents: 2311,
    label: { ru: 'Pro', en: 'Pro' },
    highlights: {
      ru: ['~83 мин ассистента', '~2500 веб-поисков', '~62 мин обзвона'],
      en: ['~83 min assistant', '~2500 web searches', '~62 min outbound'],
    },
  },
  {
    id: 'business',
    amountPlanck: 10_260_000_000n,
    priceEurCents: 11081,
    label: { ru: 'Business', en: 'Business' },
    highlights: {
      ru: ['~400 мин ассистента', '~12 000 веб-поисков', '~300 мин обзвона'],
      en: ['~400 min assistant', '~12k web searches', '~300 min outbound'],
    },
  },
];

export const PACKAGES_BY_ID: Record<string, BillingPackage> =
  Object.fromEntries(PACKAGES.map((p) => [p.id, p]));
