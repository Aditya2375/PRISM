import { useState } from "react";

// Toggling between separate animation names guarantees that React applies a
// fresh CSS animation when the same validation errors are submitted again.
export function useValidationShake() {
  const [shakeVersion, setShakeVersion] = useState(0);
  const retriggerShake = () => setShakeVersion((version) => version + 1);
  return [shakeVersion, retriggerShake];
}

export function shakeClassName(version) {
  return version % 2 === 0 ? "auth-shake-a" : "auth-shake-b";
}
