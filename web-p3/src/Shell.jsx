import "./AdminDashboard.css";
import { useState } from "react";
import { clip } from "./format";

export function Icon({name}) { const paths={grid:<><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></>,users:<><path d="M16 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="10" cy="7" r="4"/><path d="M20 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75"/></>,devices:<><rect x="3" y="4" width="18" height="13" rx="2"/><path d="M8 21h8m-4-4v4"/></>,verify:<><path d="M12 22s8-4 8-11V5l-8-3-8 3v6c0 7 8 11 8 11z"/><path d="m9 12 2 2 4-4"/></>,key:<><circle cx="8" cy="15" r="5"/><path d="m11.5 11.5 9-9 2 2-2 2 2 2-3 3-2-2-4.5 4.5"/></>,access:<><path d="M7 17 17 7M7 7h10v10"/><path d="M5 5v14h14"/></>,settings:<><circle cx="12" cy="12" r="3"/><path d="M19 13.5a7 7 0 0 0 0-3l2-1.5-2-3.5-2.3 1a7 7 0 0 0-2.6-1.5L14 2h-4l-.2 3a7 7 0 0 0-2.5 1.5L5 5.5 3 9l2 1.5a7 7 0 0 0 0 3L3 15l2 3.5 2.3-1a7 7 0 0 0 2.5 1.5L10 22h4l.2-3a7 7 0 0 0 2.5-1.5l2.3 1L21 15z"/></>,pulse:<path d="M3 12h4l3-8 4 16 3-8h4"/>,logs:<path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/>,alert:<><path d="m10.3 3.9-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.7-3.1l-8-14a2 2 0 0 0-3.4 0z"/><path d="M12 9v4m0 4h.01"/></>,backup:<><path d="M20 7v5h-5M4 17v-5h5"/><path d="M5.6 9A7 7 0 0 1 18 6l2 6M4 12l2 6a7 7 0 0 0 12.4-3"/></>,help:<><circle cx="12" cy="12" r="10"/><path d="M9.1 9a3 3 0 0 1 5.8 1c0 2-3 3-3 3m.1 4h.01"/></>};return <svg className="ad-icon-svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{paths[name]||paths.grid}</svg>; }

export function Pill({ children, tone }) {
  const t = tone ?? String(children).toLowerCase().replace(/\s+/g, "-");
  return <span className={`ad-pill ${t}`}><i />{clip(children, 24)}</span>;
}

export function Table({ headers, children }) {
  return <div className="ad-table-wrap"><table><thead><tr>{headers.map((h) => <th key={h}>{h}</th>)}</tr></thead><tbody>{children}</tbody></table></div>;
}

export function PageHead({ label, title, desc, right }) {
  return <div className="ad-heading"><div><label>{label}</label><h1>{title}</h1><p>{desc}</p></div>{right}</div>;
}

export function Modal({ title, children, close }) {
  return (
    <div className="ad-backdrop" onMouseDown={(e) => e.target === e.currentTarget && close()}>
      <section className="ad-modal" role="dialog" aria-modal="true" aria-label={title}>
        <header><h2>{title}</h2><button onClick={close} aria-label="Close">x</button></header>{children}
      </section>
    </div>
  );
}

// Sidebar and top bar in the design of the supplied admin shell. `nav` is [[group, [[key, label, icon, badge]]]].
export default function Shell({ nav, page, setPage, role, who, onSignOut, live, toast, children }) {
  const [collapsed, setCollapsed] = useState(false);
  const [drawer, setDrawer] = useState(false);
  const label = nav.flatMap(([, items]) => items).find(([k]) => k === page)?.[1] ?? "";
  return (
    <div className="admin-dash">
      <aside className={`ad-sidebar ${collapsed ? "ad-collapsed" : ""} ${drawer ? "ad-drawer-open" : ""}`}>
        <div className="ad-brand"><img src="/images/prism-emblem.png" alt="" /><div><b>P.R.I.S.M</b><small>{role.toUpperCase()}</small></div>
          <button className="ad-collapse" onClick={() => setCollapsed(!collapsed)} aria-label="Collapse the menu">&lsaquo;</button></div>
        <nav>
          {nav.map(([group, items]) => (
            <section key={group}><label>{group}</label>
              {items.map(([k, l, ic, badge]) => (
                <button key={k} title={collapsed ? l : ""} className={page === k ? "selected" : ""} onClick={() => { setPage(k); setDrawer(false); }}>
                  <span className="ad-icon"><Icon name={ic} /></span><span className="ad-nav-label">{l}</span>{badge > 0 && <em>{badge}</em>}
                </button>))}
            </section>))}
        </nav>
        <div className="ad-side-bottom"><div className="ad-health"><i /><span><b>{live}</b><small>refreshes every 5 s</small></span></div></div>
      </aside>
      {drawer && <button className="ad-scrim" aria-label="Close the menu" onClick={() => setDrawer(false)} />}
      <main className="ad-main">
        <header className="ad-top">
          <div className="ad-crumb"><button className="ad-menu" onClick={() => setDrawer(true)} aria-label="Open the menu">=</button><span>{role}</span><i>/</i><b>{label}</b></div>
          <div className="ad-top-right"><span className="ad-who">{clip(who, 48)}</span><span className="ad-vline" /><button className="ad-signout" onClick={onSignOut}>Sign out</button></div>
        </header>
        <div className="ad-content">{children}</div>
      </main>
      {toast && <div className="ad-toast" role="status">{toast}</div>}
    </div>
  );
}
