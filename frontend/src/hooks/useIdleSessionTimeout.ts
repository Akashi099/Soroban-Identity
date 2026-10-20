import { useEffect, useRef } from "react";

export const DEFAULT_IDLE_TIMEOUT_MS = 15 * 60 * 1000;
const ACTIVITY_EVENTS = ["pointerdown", "keydown", "mousemove", "scroll", "touchstart"] as const;

export function getIdleTimeoutMs(value = import.meta.env.VITE_SESSION_IDLE_TIMEOUT_MS): number {
  if (value === undefined || value === "") return DEFAULT_IDLE_TIMEOUT_MS;
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : DEFAULT_IDLE_TIMEOUT_MS;
}

/** Disconnect an active wallet after a continuous period without user input. */
export function useIdleSessionTimeout(
  active: boolean,
  onIdle: () => void | Promise<void>,
  timeoutMs = getIdleTimeoutMs()
): void {
  const onIdleRef = useRef(onIdle);
  onIdleRef.current = onIdle;

  useEffect(() => {
    if (!active || !Number.isFinite(timeoutMs) || timeoutMs <= 0) return;

    let timer: ReturnType<typeof setTimeout> | undefined;
    let expired = false;
    const resetTimer = () => {
      if (expired) return;
      clearTimeout(timer);
      timer = setTimeout(() => {
        expired = true;
        void Promise.resolve(onIdleRef.current()).catch((error: unknown) => {
          console.error("Unable to end idle wallet session:", error);
        });
      }, timeoutMs);
    };

    ACTIVITY_EVENTS.forEach((eventName) =>
      window.addEventListener(eventName, resetTimer, { passive: true })
    );
    resetTimer();

    return () => {
      clearTimeout(timer);
      ACTIVITY_EVENTS.forEach((eventName) => window.removeEventListener(eventName, resetTimer));
    };
  }, [active, timeoutMs]);
}
