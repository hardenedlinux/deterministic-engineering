/** Freeze already-owned data. Callers clone external inputs before sharing a result. */
export function deepFreeze<T>(value:T,seen=new WeakSet<object>()):T {
  if(!value||typeof value!=='object'||seen.has(value))return value;
  seen.add(value);for(const child of Object.values(value))deepFreeze(child,seen);
  return Object.freeze(value);
}
