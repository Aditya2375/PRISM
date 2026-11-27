import { useEffect, useRef, useState } from "react";

const reduced = () => typeof matchMedia === "function" && matchMedia("(prefers-reduced-motion: reduce)").matches;

// Original mark: a triangle (the prism) with one beam in and two out.
export function Mark({ size = 28, draw = false }) {
  return (
    <svg className={`mark ${draw ? "draw" : ""}`} width={size} height={size} viewBox="0 0 32 32" aria-hidden="true">
      <path d="M16 5.5 26.5 24.5H5.5Z" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinejoin="round" pathLength="1" />
      <path d="M1.5 17.5 11.4 16.4" stroke="#e8ecf1" strokeWidth="1.5" strokeLinecap="round" pathLength="1" />
      <path d="M20.4 17.6 30.5 13.6M21 20.4 30.5 19.8" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" opacity=".8" pathLength="1" />
    </svg>
  );
}

// Counts up once when the value first appears or changes; static for people who asked for less motion.
export function Count({ value }) {
  const [shown, setShown] = useState(reduced() ? value : 0);
  const from = useRef(0);
  useEffect(() => {
    if (reduced()) { setShown(value); return undefined; }
    let raf; const t0 = performance.now(); const a = from.current; const dur = 650;
    const tick = (t) => {
      const p = Math.min(1, (t - t0) / dur);
      setShown(Math.round(a + (value - a) * (1 - Math.pow(1 - p, 3))));
      if (p < 1) raf = requestAnimationFrame(tick); else from.current = value;
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [value]);
  return <>{shown}</>;
}

export function Reveal({ children, delay = 0, as: Tag = "div", className = "" }) {
  return <Tag className={`reveal ${className}`} style={{ "--d": `${delay}ms` }}>{children}</Tag>;
}

export function TopBar({ title, nav, right }) {
  return (
    <header className="top">
      <div className="top-in">
        <a className="brand" href="#top" aria-label="P.R.I.S.M home"><Mark size={22} /><b>P.R.I.S.M</b><span>{title}</span></a>
        {nav && <nav aria-label="Sections">{nav.map(([id, l]) => <a key={id} href={`#${id}`}>{l}</a>)}</nav>}
        <div className="top-right">{right}</div>
      </div>
    </header>
  );
}

export function Pill({ tone = "muted", children }) {
  return <span className={`pill ${tone}`}><i />{children}</span>;
}

export function Card({ id, title, aside, children, tone = "" }) {
  return (
    <section id={id} className={`card ${tone}`}>
      <div className="card-h"><h2>{title}</h2>{aside}</div>
      {children}
    </section>
  );
}
