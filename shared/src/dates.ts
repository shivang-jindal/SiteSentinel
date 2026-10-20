/**
 * Date helpers.
 *
 * Everything persisted is a UTC ISO-8601 timestamp or a calendar `YYYY-MM-DD`
 * date. Timezone-sensitive scheduling (reminders) uses the organization's
 * configured IANA timezone via `Intl.DateTimeFormat`, so daylight-saving
 * transitions are handled by the platform rather than by hand-rolled offsets.
 */

export function todayIso(timezone = 'UTC'): string {
  return formatDateInTimeZone(new Date(), timezone);
}

export function formatDateInTimeZone(date: Date, timezone: string): string {
  const formatter = new Intl.DateTimeFormat('en-CA', {
    timeZone: timezone,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
  });
  return formatter.format(date);
}

/** `YYYY-MM-DD` -> `YYYY-MM-DDTHH:MM:SSZ` (start of that UTC day). */
export function dateToUtcIsoStart(date: string): string {
  return `${date}T00:00:00.000Z`;
}

/** `YYYY-MM-DD` -> next day start, exclusive range end. */
export function dateToUtcIsoEndExclusive(date: string): string {
  const value = new Date(`${date}T00:00:00.000Z`);
  value.setUTCDate(value.getUTCDate() + 1);
  return value.toISOString();
}

export function addDaysIso(date: string, days: number): string {
  const value = new Date(`${date}T00:00:00.000Z`);
  value.setUTCDate(value.getUTCDate() + days);
  return value.toISOString().slice(0, 10);
}

/** Whole days between two ISO dates (`to - from`). Positive when `to` is later. */
export function daysBetweenIso(from: string, to: string): number {
  const a = Date.parse(`${from}T00:00:00.000Z`);
  const b = Date.parse(`${to}T00:00:00.000Z`);
  return Math.round((b - a) / 86_400_000);
}

export function isValidIsoDate(value: string): boolean {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  const parsed = new Date(`${value}T00:00:00.000Z`);
  return !Number.isNaN(parsed.getTime()) && parsed.toISOString().slice(0, 10) === value;
}

/**
 * Convert a wall-clock time in `timezone` to a UTC instant.
 * Returns `null` for a local time that does not exist (spring-forward gap).
 */
export function zonedWallClockToUtc(
  date: string,
  time: string,
  timezone: string,
): Date | null {
  const target = Date.parse(`${date}T${time}:00.000Z`);
  if (Number.isNaN(target)) return null;

  for (let offsetMinutes = -14 * 60; offsetMinutes <= 14 * 60; offsetMinutes += 15) {
    const candidate = new Date(target - offsetMinutes * 60_000);
    if (formatDateInTimeZone(candidate, timezone) === date) {
      const parts = new Intl.DateTimeFormat('en-GB', {
        timeZone: timezone,
        hour: '2-digit',
        minute: '2-digit',
        hour12: false,
      }).format(candidate);
      if (parts === time) return candidate;
    }
  }
  return null;
}

/** Minutes since midnight in `timezone` for an instant. */
export function minutesSinceMidnightInZone(instant: Date, timezone: string): number {
  const parts = new Intl.DateTimeFormat('en-GB', {
    timeZone: timezone,
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  }).formatToParts(instant);
  const hour = Number(parts.find((part) => part.type === 'hour')?.value ?? '0');
  const minute = Number(parts.find((part) => part.type === 'minute')?.value ?? '0');
  return hour * 60 + minute;
}

export function isValidTimeZone(timezone: string): boolean {
  try {
    new Intl.DateTimeFormat('en-US', { timeZone: timezone });
    return true;
  } catch {
    return false;
  }
}

export function formatIsoTimestamp(date: Date | string | null): string | null {
  if (date === null) return null;
  const value = typeof date === 'string' ? new Date(date) : date;
  return Number.isNaN(value.getTime()) ? null : value.toISOString();
}

/* -------------------------------------------------------------------------- */
/* Maintenance-window recurrence (Part F / F3.7)                              */
/* -------------------------------------------------------------------------- */

export interface MaintenanceRecurrence {
  kind: 'none' | 'daily' | 'weekly' | 'monthly';
  /** For weekly/monthly: 1 = Monday ... 7 = Sunday (ISO). Ignored for daily. */
  weekdays?: number[];
  /** Local wall-clock time `HH:MM` in `timezone` at which each occurrence starts. */
  timeOfDay?: string;
  /** Length of each occurrence, in minutes. Required for recurring windows. */
  durationMinutes?: number;
}

export interface MaintenanceOccurrence {
  start: Date;
  end: Date;
}

/**
 * Expands a maintenance window into concrete UTC occurrences.
 *
 * `anchors` are the absolute UTC start/end instants stored with the window.
 * For a one-time window the result is always exactly that window. For a
 * recurring window every wall-clock occurrence in `[from, to]` is derived from
 * the local calendar day in `timezone`, so daylight-saving transitions shift the
 * UTC instant while keeping the local time the operator chose.
 *
 * The search range is deliberately widened by one day on each side so a
 * timezone offset can never hide an occurrence that starts on the boundary.
 */
export function maintenanceOccurrences(input: {
  startsAt: Date;
  endsAt: Date;
  timezone: string;
  recurrence: MaintenanceRecurrence | null;
  from: Date;
  to: Date;
}): MaintenanceOccurrence[] {
  const { startsAt, endsAt, timezone, recurrence, from, to } = input;

  if (!recurrence || recurrence.kind === 'none') {
    if (endsAt.getTime() <= from.getTime() || startsAt.getTime() >= to.getTime()) return [];
    return [{ start: startsAt, end: endsAt }];
  }

  const durationMinutes = recurrence.durationMinutes ?? 60;
  if (!Number.isFinite(durationMinutes) || durationMinutes <= 0) return [];

  const minutes =
    recurrence.timeOfDay && /^\d{2}:\d{2}$/.test(recurrence.timeOfDay)
      ? (Number(recurrence.timeOfDay.slice(0, 2)) * 60 + Number(recurrence.timeOfDay.slice(3, 5)))
      : minutesSinceMidnightInZone(startsAt, timezone);

  const weekdays = recurrence.weekdays?.length ? recurrence.weekdays : [isoWeekdayInZone(startsAt, timezone)];
  const weekdaysSet = new Set(weekdays);
  // Monthly recurrence keeps the local day-of-month the operator anchored to,
  // which is what a person means by "the 3rd of every month".
  const anchorDayOfMonth = Number(formatDateInTimeZone(startsAt, timezone).slice(8, 10));

  const occurrenceDurationMs = durationMinutes * 60_000;
  const windowStart = from.getTime() - occurrenceDurationMs - 24 * 3_600_000;
  const windowEnd = to.getTime() + 24 * 3_600_000;

  const occurrences: MaintenanceOccurrence[] = [];
  const cursor = new Date(windowStart);
  // Bounded so a pathological range can never spin forever.
  for (let guard = 0; guard < 400 && cursor.getTime() <= windowEnd; guard += 1) {
    const day = formatDateInTimeZone(cursor, timezone);
    const matches =
      recurrence.kind === 'daily'
        ? true
        : recurrence.kind === 'weekly'
          ? weekdaysSet.has(isoWeekdayInZone(cursor, timezone))
          : Number(day.slice(8, 10)) === anchorDayOfMonth;

    if (matches) {
      const hours = Math.floor(minutes / 60);
      const minuteOfHour = minutes % 60;
      const start = zonedWallClockToUtc(day, `${pad2(hours)}:${pad2(minuteOfHour)}`, timezone);
      if (start) {
        const end = new Date(start.getTime() + occurrenceDurationMs);
        if (end.getTime() > from.getTime() && start.getTime() < to.getTime()) {
          occurrences.push({ start, end });
        }
      }
    }
    cursor.setUTCDate(cursor.getUTCDate() + 1);
  }

  return occurrences.sort((a, b) => a.start.getTime() - b.start.getTime());
}

/** `true` when `at` falls inside any occurrence of the window. */
export function isMaintenanceActive(input: {
  startsAt: Date;
  endsAt: Date;
  timezone: string;
  recurrence: MaintenanceRecurrence | null;
  at: Date;
}): boolean {
  return maintenanceOccurrences({ ...input, from: input.at, to: input.at }).length > 0;
}

export function isoWeekdayInZone(instant: Date, timezone: string): number {
  const day = formatDateInTimeZone(instant, timezone);
  return isoWeekdayOfDate(day);
}

/** `YYYY-MM-DD` -> ISO weekday (1 = Monday ... 7 = Sunday). */
export function isoWeekdayOfDate(date: string): number {
  const value = new Date(`${date}T00:00:00.000Z`);
  const day = value.getUTCDay();
  return day === 0 ? 7 : day;
}

function pad2(value: number): string {
  return String(value).padStart(2, '0');
}