import { useMemo, useState } from "react";
import "./UserDashboard.css";

const navGroups = [
  { label: "WORKSPACE", items: [["Overview", "◫"], ["My Identity", "◎"], ["Trusted Devices", "▣"], ["Security Keys", "⌑"], ["Access Permissions", "⇄"], ["Activity & Sessions", "◷"], ["Notifications", "♧"]] },
  { label: "PREFERENCES", items: [["Settings", "⚙"], ["Help & Support", "?〫"]] },
];
const activitySeed = [
  { title: "Successful login", detail: "Chrome on macOS · San Francisco, US", time: "Today, 9:42 AM", type: "Authentication", icon: "↗", tone: "green" },
  { title: "Security key rotated", detail: "ML-DSA · Key version 04", time: "Yesterday, 4:18 PM", type: "Security", icon: "⌑", tone: "violet" },
  { title: "New device registered", detail: "MacBook Pro 14 · macOS 15.2", time: "Nov 22, 2026 · 11:06 AM", type: "Devices", icon: "▣", tone: "blue" },
  { title: "Permission granted", detail: "Notion · Read profile", time: "Nov 20, 2026 · 2:31 PM", type: "Permissions", icon: "⇄", tone: "amber" },
];
const devicesSeed = [
  { name: "MacBook Pro 14″", type: "Laptop", os: "macOS 15.2", registered: "Nov 22, 2026", active: "Just now", status: "Active", key: "Active", icon: "▰" },
  { name: "iPhone 16 Pro", type: "Mobile", os: "iOS 19.1", registered: "Oct 14, 2026", active: "2 hours ago", status: "Active", key: "Active", icon: "▯" },
  { name: "ThinkPad X1 Carbon", type: "Laptop", os: "Windows 11", registered: "Aug 03, 2026", active: "Nov 18, 2026", status: "Revoked", key: "Revoked", icon: "▰" },
];
const serviceSeed = [
  { name: "Notion", category: "Productivity", scope: "Read profile", date: "Nov 20, 2026", last: "Today, 8:10 AM", status: "Connected", icon: "N", color: "notion" },
  { name: "GitHub", category: "Developer tools", scope: "Profile · Email", date: "Oct 08, 2026", last: "Yesterday", status: "Connected", icon: "⌘", color: "github" },
  { name: "Figma", category: "Design", scope: "Read profile", date: "Sep 12, 2026", last: "Nov 21, 2026", status: "Connected", icon: "F", color: "figma" },
  { name: "Linear", category: "Productivity", scope: "Profile · Email", date: "Jul 30, 2026", last: "Nov 19, 2026", status: "Connected", icon: "↗", color: "linear" },
];
const notificationSeed = [
  { title: "Security key rotated successfully", description: "Your ML-DSA key is now at version 04.", time: "Yesterday · 4:18 PM", severity: "Info", read: false, icon: "⌑" },
  { title: "New device registered", description: "MacBook Pro 14 was added to your trusted devices.", time: "Nov 22 · 11:06 AM", severity: "Success", read: false, icon: "▣" },
  { title: "Sign-in from a new location", description: "A sign-in was detected from San Francisco, US.", time: "Nov 21 · 9:42 AM", severity: "Review", read: true, icon: "⌖" },
];

function Badge({ children, kind }) { return <span className={`badge ${kind || String(children).toLowerCase().replaceAll(" ", "-")}`}>{children}</span>; }
function Icon({ children, className = "" }) { return <span aria-hidden="true" className={`ui-icon ${className}`}>{children}</span>; }

export default function UserDashboard({ email = "alex.morgan@prism.id", onSignOut }) {
  const displayName = email.split("@")[0].split(/[._-]/).map((part) => part[0]?.toUpperCase() + part.slice(1)).join(" ") || "Alex Morgan";
  const [page, setPage] = useState("Overview");
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [devices, setDevices] = useState(devicesSeed);
  const [services, setServices] = useState(serviceSeed);
  const [notifications, setNotifications] = useState(notificationSeed);
  const [activities, setActivities] = useState(activitySeed);
  const [query, setQuery] = useState("");
  const [category, setCategory] = useState("All activity");
  const [toast, setToast] = useState("");
  const [showProfile, setShowProfile] = useState(false);
  const [showAddDevice, setShowAddDevice] = useState(false);
  const [deviceName, setDeviceName] = useState("");
  const [dark, setDark] = useState(true);
  const unread = notifications.filter((note) => !note.read).length;
  const filteredActivity = useMemo(() => activities.filter((item) => (category === "All activity" || item.type === category) && `${item.title} ${item.detail}`.toLowerCase().includes(query.toLowerCase())), [activities, category, query]);
  function flash(message) { setToast(message); window.setTimeout(() => setToast(""), 2600); }
  function addActivity(title, detail, type = "Devices") { setActivities((prev) => [{ title, detail, time: "Just now", type, icon: "✦", tone: "blue" }, ...prev]); }
  function revokeDevice(index) { setDevices((prev) => prev.map((device, i) => i === index ? { ...device, status: "Revoked", key: "Revoked" } : device)); addActivity("Device revoked", devices[index].name); flash(`${devices[index].name} access revoked`); }
  function revokeService(index) { setServices((prev) => prev.map((service, i) => i === index ? { ...service, status: "Revoked" } : service)); addActivity("Permission revoked", services[index].name, "Permissions"); flash(`${services[index].name} access revoked`); }
  function addDevice(event) { event.preventDefault(); if (!deviceName.trim()) return; setDevices((prev) => [{ name: deviceName.trim(), type: "New device", os: "This device", registered: "Today", active: "Just now", status: "Pending", key: "Pending", icon: "▣" }, ...prev]); addActivity("New device registered", deviceName.trim()); setDeviceName(""); setShowAddDevice(false); flash("Device enrolment started"); }
  function markRead(index) { setNotifications((prev) => prev.map((note, i) => i === index ? { ...note, read: true } : note)); }
  function markAllRead() { setNotifications((prev) => prev.map((note) => ({ ...note, read: true }))); }

  return <div className={`dashboard-shell ${dark ? "theme-dark" : "theme-light"}`}>
<aside className={`sidebar ${sidebarCollapsed ? "collapsed" : ""}`}>
  <div className="sidebar-brand-row">
    <button className="brand-lockup" onClick={() => setPage("Overview")} aria-label="P.R.I.S.M home">
      <img
        src="/images/prism-emblem.png"
        alt="P.R.I.S.M Logo"
        className="brand-logo"
      />
      <span>
        <b>P.R.I.S.M</b>
        <small>IDENTITY PLATFORM</small>
      </span>
    </button>

    <button
      className="sidebar-toggle"
      onClick={() => setSidebarCollapsed(!sidebarCollapsed)}
      aria-label={sidebarCollapsed ? "Expand sidebar" : "Collapse sidebar"}
      title={sidebarCollapsed ? "Expand sidebar" : "Collapse sidebar"}
    >
      {sidebarCollapsed ? "»" : "«"}
    </button>
  </div>

  <div className="workspace-switch">
    <span className="workspace-dot">A</span>
    <span>
      <b>Acme workspace</b>
      <small>Personal account</small>
    </span>
    <span className="switch-chevron">⌄</span>
  </div>

  <nav className="side-nav">
    {navGroups.map((group) => (
      <div className="nav-group" key={group.label}>
        <p className="nav-label">{group.label}</p>
        {group.items.map(([label, icon]) => (
          <button
            key={label}
            onClick={() => setPage(label)}
            className={`nav-item ${page === label ? "selected" : ""}`}
            title={sidebarCollapsed ? label : ""}
          >
            <Icon>{icon}</Icon>
            <span>{label}</span>
            {label === "Notifications" && unread > 0 && (
              <b className="nav-count">{unread}</b>
            )}
          </button>
        ))}
      </div>
    ))}
  </nav>

  <div className="sidebar-bottom">
    <div className="security-mini">
      <span className="mini-shield">✦</span>
      <div>
        <b>All systems secure</b>
        <small>Last checked just now</small>
      </div>
      <span className="pulse-dot" />
    </div>

    <button className="help-link" onClick={() => setPage("Help & Support")}>
      <Icon>◌</Icon>
      Help center
      <span>↗</span>
    </button>
  </div>
</aside>
    <main className="dashboard-main">
      <header className="topbar"><div className="breadcrumbs"><span>Workspace</span><b>/</b><strong>{page}</strong></div><div className="topbar-actions"><button className="icon-button notification-bell" aria-label="Notifications" onClick={() => setPage("Notifications")}>♧{unread > 0 && <i />}</button><span className="top-divider" /><button className="profile-trigger" onClick={() => setShowProfile(!showProfile)}><span className="avatar">{displayName.split(" ").map((w) => w[0]).join("").slice(0, 2)}</span><span className="profile-copy"><b>{displayName}</b><small>Personal account</small></span><span className="switch-chevron">⌄</span></button>{showProfile && <div className="profile-menu"><b>{email}</b><button onClick={() => { setPage("My Identity"); setShowProfile(false); }}>View profile</button><button onClick={onSignOut}>Sign out</button></div>}</div></header>
      <div key={page} className="page-content page-transition">
        {page === "Overview" && <Overview name={displayName} devices={devices} services={services} activities={activities} notifications={notifications} onNavigate={setPage} />}
        {page === "My Identity" && <Identity name={displayName} email={email} onSave={() => flash("Profile details saved")} />}
        {page === "Trusted Devices" && <Devices devices={devices} onAdd={() => setShowAddDevice(true)} onRevoke={revokeDevice} onDetails={(name) => flash(`${name} · Device details`)} />}
        {page === "Security Keys" && <Keys onRotate={() => flash("Key rotation request submitted")} />}
        {page === "Access Permissions" && <Permissions services={services} onRevoke={revokeService} />}
        {page === "Activity & Sessions" && <ActivityPage activities={filteredActivity} allActivities={activities} sessions={devices.filter((d) => d.status === "Active")} query={query} setQuery={setQuery} category={category} setCategory={setCategory} onTerminate={(name) => { flash(`${name} session terminated`); addActivity("Session terminated", name, "Authentication"); }} />}
        {page === "Notifications" && <Notifications items={notifications} onRead={markRead} onReadAll={markAllRead} />}
        {page === "Settings" && <Settings dark={dark} setDark={setDark} onSave={() => flash("Settings saved")} />}
        {page === "Help & Support" && <Help onContact={() => flash("Support request started")} />}
      </div>
    </main>
    {toast && <div className="toast"><span>✓</span>{toast}</div>}
    {showAddDevice && <div className="modal-backdrop" onClick={() => setShowAddDevice(false)}><form className="dialog" onSubmit={addDevice} onClick={(e) => e.stopPropagation()}><button type="button" className="dialog-close" onClick={() => setShowAddDevice(false)}>×</button><span className="dialog-icon">▣</span><h2>Register a new device</h2><p>Give this device a name to start secure enrolment.</p><label htmlFor="device-name">Device name</label><input id="device-name" autoFocus placeholder="e.g. Work laptop" value={deviceName} onChange={(e) => setDeviceName(e.target.value)} /><div className="dialog-actions"><button type="button" className="button secondary" onClick={() => setShowAddDevice(false)}>Cancel</button><button className="button primary">Continue enrolment <span>→</span></button></div></form></div>}
  </div>;
}

function PageHeading({ eyebrow = "ACCOUNT SECURITY", title, description, action }) { return <div className="page-heading"><div><p className="eyebrow">{eyebrow}</p><h1>{title}</h1><p className="page-description">{description}</p></div>{action}</div>; }
function Panel({ title, subtitle, action, children, className = "" }) { return <section className={`panel ${className}`}><div className="panel-heading"><div><h2>{title}</h2>{subtitle && <p>{subtitle}</p>}</div>{action}</div>{children}</section>; }
function Overview({ name, devices, services, activities, notifications, onNavigate }) {
  const activeDevices = devices.filter((d) => d.status === "Active").length;
  return <>
    <div className="welcome-row"><div><p className="eyebrow">WEDNESDAY, NOVEMBER 26, 2026 <span className="date-spark">✦</span></p><h1>Good morning, {name.split(" ")[0]} <span className="wave">✳</span></h1><p className="page-description">Here’s your identity security at a glance.</p></div><button className="button secondary date-button">◷ <span>Last 30 days</span><b>⌄</b></button></div>
    <section className="security-banner"><div className="banner-icon">✦</div><div className="banner-copy"><b>Your account is looking good</b><span>All security checks passed. Your identity is protected.</span></div><span className="banner-status"><i /> PROTECTED</span><span className="banner-decoration">✧</span></section>
    <div className="stat-grid">
      <StatCard title="Identity status" icon="◎" value="Verified" detail="Identity confirmed" color="purple" change="100%" onClick={() => onNavigate("My Identity")} />
      <StatCard title="Trusted devices" icon="▣" value={activeDevices} detail="registered devices" color="blue" change="+1 this month" onClick={() => onNavigate("Trusted Devices")} />
      <StatCard title="Active sessions" icon="◷" value="2" detail="across your devices" color="cyan" change="All yours" onClick={() => onNavigate("Activity & Sessions")} />
      <StatCard title="Security keys" icon="⌑" value="v04" detail="ML-DSA · Active" color="green" change="Up to date" onClick={() => onNavigate("Security Keys")} />
      <StatCard title="Connected services" icon="⇄" value={services.filter((s) => s.status === "Connected").length} detail="with access to your ID" color="amber" change="Review access" onClick={() => onNavigate("Access Permissions")} />
    </div>
    <div className="overview-columns"><Panel title="Recent activity" subtitle="Your latest account events" action={<button className="text-action" onClick={() => onNavigate("Activity & Sessions")}>View all <span>→</span></button>} className="activity-panel"><ActivityList items={activities.slice(0, 4)} /></Panel><Panel title="Security notifications" subtitle={`${notifications.filter((n) => !n.read).length} unread notifications`} action={<button className="text-action" onClick={() => onNavigate("Notifications")}>See all <span>→</span></button>} className="notifications-panel"><div className="notification-preview">{notifications.slice(0, 3).map((note, i) => <div className={`preview-item ${!note.read ? "unread" : ""}`} key={note.title}><span className="preview-icon">{note.icon}</span><div><b>{note.title}</b><p>{note.description}</p><small>{note.time}</small></div>{!note.read && <i />}</div>)}</div></Panel></div>
    <div className="overview-footer"><span><i className="pulse-dot" /> Last security scan · 2 minutes ago</span><button onClick={() => onNavigate("Security Keys")}>View security details <span>↗</span></button></div>
  </>;
}
function StatCard({ title, icon, value, detail, color, change, onClick }) { return <button className="stat-card" onClick={onClick}><div className="stat-top"><span className={`stat-icon ${color}`}>{icon}</span><span className="stat-arrow">↗</span></div><p>{title}</p><div className="stat-value">{value}</div><div className="stat-bottom"><span>{detail}</span><small className={color}>{change}</small></div></button>; }
function ActivityList({ items }) { return <div className="activity-list">{items.map((item, index) => <div className="activity-row" key={`${item.title}-${index}`}><span className={`activity-icon ${item.tone || "blue"}`}>{item.icon}</span><div className="activity-info"><b>{item.title}</b><small>{item.detail}</small></div><time>{item.time}</time></div>)}</div>; }
function Identity({ name, email, onSave }) { const [editing, setEditing] = useState(false); return <><PageHeading title="My identity" description="Manage your personal details and how you authenticate." action={<button className={`button ${editing ? "primary" : "secondary"}`} onClick={() => { if (editing) onSave(); setEditing(!editing); }}>{editing ? "Save changes" : "✎ Edit profile"}</button>} /><div className="identity-layout"><Panel title="Personal information" subtitle="Your verified identity details" className="identity-panel"><div className="identity-banner"><span className="identity-avatar">{name.split(" ").map((w) => w[0]).join("").slice(0, 2)}</span><div><b>{name}</b><small>Personal account · Member since March 2024</small></div><Badge kind="verified">✓ Verified</Badge></div><div className="field-grid">{[["FULL NAME", name], ["UNIQUE IDENTITY ID", "PR-7F2A-91D4-C830"], ["USERNAME", `@${email.split("@")[0]}`], ["EMAIL ADDRESS", email], ["ACCOUNT CREATED", "March 14, 2024"], ["VERIFICATION LEVEL", "Enhanced · Level 2"]].map(([label, value]) => <label className="read-field" key={label}><span>{label}</span><input readOnly={!editing} defaultValue={value} /></label>)}</div></Panel><Panel title="Authentication methods" subtitle="Ways to verify it’s really you" action={<button className="text-action" onClick={() => setEditing(true)}>Manage <span>→</span></button>}><Method icon="⌑" title="Security key" detail="ML-DSA · Added Mar 14, 2024" badge="Primary" /><Method icon="▯" title="Passkey" detail="iCloud Keychain · Added Oct 02, 2026" badge="Active" /><Method icon="✉" title="Recovery email" detail={email} badge="Verified" /></Panel><Panel title="Verification details" subtitle="Identity verification completed Mar 14, 2024"><div className="verification-detail"><span className="verified-stamp">✓</span><div><b>Identity verified</b><p>Your identity has been confirmed and is in good standing.</p><small>Verification reference · VR-2024-0314-82</small></div></div></Panel></div></>; }
function Method({ icon, title, detail, badge }) { return <div className="method-row"><span className="method-icon">{icon}</span><span className="method-copy"><b>{title}</b><small>{detail}</small></span><Badge kind="active">{badge}</Badge><button className="more-button" aria-label={`Manage ${title}`}>···</button></div>; }
function Devices({ devices, onAdd, onRevoke, onDetails }) { return <><PageHeading title="Trusted devices" description="Devices authorized to access your P.R.I.S.M identity." action={<button className="button primary" onClick={onAdd}>＋ Register device</button>} /><div className="device-summary"><span><b>{devices.filter((d) => d.status === "Active").length}</b> active devices</span><span className="summary-divider" /><span><b>{devices.length}</b> total enrolled</span><span className="summary-spacer" /><span className="device-hint"><i className="pulse-dot" /> Device keys are checked continuously</span></div><Panel title="Your devices" subtitle="Review and manage device access" className="table-panel"><div className="table-scroll"><table><thead><tr><th>DEVICE</th><th>OPERATING SYSTEM</th><th>REGISTERED</th><th>LAST ACTIVE</th><th>STATUS</th><th>DEVICE KEY</th><th /></tr></thead><tbody>{devices.map((device, i) => <tr key={`${device.name}-${i}`}><td><div className="device-cell"><span className="device-glyph">{device.icon}</span><span><b>{device.name}</b><small>{device.type}</small></span></div></td><td>{device.os}</td><td>{device.registered}</td><td>{device.active}</td><td><Badge>{device.status}</Badge></td><td><span className={`key-state ${device.key === "Active" ? "good" : "muted"}`}><i /> {device.key}</span></td><td><button className="more-button" onClick={() => onDetails(device.name)}>···</button>{device.status === "Active" && <button className="row-action danger" onClick={() => onRevoke(i)}>Revoke</button>}</td></tr>)}</tbody></table></div></Panel><div className="info-callout"><span>ⓘ</span><p><b>Keep your devices up to date.</b> Remove devices you no longer use to keep your identity secure.</p><button onClick={onAdd}>Learn more ↗</button></div></>; }
function Keys({ onRotate }) { return <><PageHeading title="Security keys" description="Cryptographic keys protect your identity across every interaction." action={<button className="button secondary" onClick={onRotate}>↻ Request rotation</button>} /><div className="key-hero"><div className="key-hero-top"><span className="key-hero-symbol">⌑</span><Badge kind="active">● Active</Badge></div><p className="eyebrow">CURRENT IDENTITY KEY</p><div className="key-version">Version <b>04</b><span>·</span> ML-DSA-65</div><div className="key-fingerprint"><span>PUBLIC KEY FINGERPRINT</span><code>SHA3-256&nbsp; 8D4A 29C7 1E6B 3F90 5B12 73AC 42DD 8E10</code><button onClick={() => onRotate("copied")}>▢</button></div><span className="key-hero-orbit orbit-one" /><span className="key-hero-orbit orbit-two" /></div><div className="key-metrics"><div><span>ALGORITHM</span><b>ML-DSA-65</b><small>FIPS 204 · Post-quantum</small></div><div><span>CREATED</span><b>November 22, 2026</b><small>09:14:32 UTC</small></div><div><span>LAST ROTATION</span><b>November 22, 2026</b><small>Automatic rotation</small></div><div><span>EXPIRATION</span><b>No expiration</b><small>Rotates every 180 days</small></div></div><Panel title="Key rotation history" subtitle="Previous key versions and lifecycle events" className="rotation-panel"><div className="rotation-list">{[["04", "Current key activated", "ML-DSA-65 · Nov 22, 2026", "Active"], ["03", "Key rotation completed", "ML-DSA-65 · Aug 25, 2026", "Expired"], ["02", "Key rotation completed", "ML-DSA-65 · May 26, 2026", "Expired"], ["01", "Initial key created", "ML-DSA-65 · Mar 14, 2024", "Expired"]].map(([v, title, detail, status], i) => <div className="rotation-row" key={v}><span className={`rotation-dot ${i === 0 ? "current" : ""}`} /><span className="rotation-version">v{v}</span><span className="rotation-copy"><b>{title}</b><small>{detail}</small></span><Badge>{status}</Badge><span className="rotation-kind">{i === 0 ? "Current" : "Historical"}</span></div>)}</div></Panel><div className="info-callout warning-callout"><span>✦</span><p><b>Key material is protected.</b> Private keys are generated and stored securely on your devices. P.R.I.S.M never displays private key material.</p><button onClick={() => onRotate()}>Key security ↗</button></div></>; }
function Permissions({ services, onRevoke }) { return <><PageHeading title="Access permissions" description="Control which applications can access your identity and profile." action={<button className="button secondary" onClick={() => alert("Permission history is shown in Activity & Sessions.")}>◷ Permission history</button>} /><div className="permission-summary"><div><span className="summary-icon">⇄</span><span><b>{services.filter((s) => s.status === "Connected").length} connected apps</b><small>Review access whenever you like</small></span></div><span className="permission-note"><i className="pulse-dot" /> Your identity stays in your control</span></div><Panel title="Connected applications" subtitle="Applications with access to your P.R.I.S.M identity" className="table-panel"><div className="table-scroll"><table><thead><tr><th>APPLICATION</th><th>PERMISSION GRANTED</th><th>DATE GRANTED</th><th>LAST ACCESSED</th><th>STATUS</th><th /></tr></thead><tbody>{services.map((service, i) => <tr key={service.name}><td><div className="service-cell"><span className={`service-logo ${service.color}`}>{service.icon}</span><span><b>{service.name}</b><small>{service.category}</small></span></div></td><td>{service.scope}</td><td>{service.date}</td><td>{service.last}</td><td><Badge>{service.status}</Badge></td><td>{service.status === "Connected" && <button className="row-action danger" onClick={() => onRevoke(i)}>Revoke</button>}</td></tr>)}</tbody></table></div></Panel><div className="permission-footnote"><span>ⓘ</span><p>Apps only receive the specific information listed in their permissions. You can revoke access at any time.</p></div></>; }
function ActivityPage({ activities, allActivities, sessions, query, setQuery, category, setCategory, onTerminate }) { return <><PageHeading title="Activity & sessions" description="Monitor sign-ins, account events, and active sessions." /><div className="session-header"><div><p className="eyebrow">ACTIVE SESSIONS</p><h2>{sessions.length} active sessions</h2><p>Devices currently signed in to your account.</p></div><span className="session-secure"><i className="pulse-dot" /> All sessions are secure</span></div><div className="session-grid">{sessions.map((device, i) => <div className="session-card" key={device.name}><div className="session-card-top"><span className="device-glyph">{device.icon}</span><Badge kind="active">Current</Badge></div><b>{device.name}</b><small>{device.os} · {i === 0 ? "Chrome 130" : "Safari 19"}</small><div className="session-meta"><span>LOGIN TIME<strong>{i === 0 ? "Today, 9:42 AM" : "Today, 7:18 AM"}</strong></span><span>LAST ACTIVITY<strong>{i === 0 ? "Just now" : "12 min ago"}</strong></span></div><button className="row-action danger" onClick={() => onTerminate(device.name)}>Terminate session</button></div>)}</div><Panel title="Activity history" subtitle={`${allActivities.length} recent events`} className="history-panel"><div className="activity-tools"><label className="search-box"><span>⌕</span><input placeholder="Search activity..." value={query} onChange={(e) => setQuery(e.target.value)} /><kbd>⌘ K</kbd></label><select value={category} onChange={(e) => setCategory(e.target.value)}><option>All activity</option><option>Authentication</option><option>Security</option><option>Devices</option><option>Permissions</option></select><button className="button secondary filter-button">▤ Date range</button></div>{activities.length ? <ActivityList items={activities} /> : <div className="empty-state">No activity matches your search.</div>}</Panel></>; }
function Notifications({ items, onRead, onReadAll }) { return <><PageHeading title="Notifications" description="Security updates and important activity on your account." action={<button className="button secondary" onClick={onReadAll}>✓ Mark all as read</button>} /><div className="notification-tabs"><button className="active">All notifications <span>{items.length}</span></button><button>Unread <span>{items.filter((n) => !n.read).length}</span></button></div><Panel title="Recent notifications" subtitle="The latest updates from your account"><div className="full-notifications">{items.map((note, i) => <div className={`full-note ${note.read ? "read" : ""}`} key={note.title}><span className={`full-note-icon ${note.severity.toLowerCase()}`}>{note.icon}</span><div className="full-note-copy"><div><b>{note.title}</b><Badge kind={note.severity.toLowerCase()}>{note.severity}</Badge></div><p>{note.description}</p><small>{note.time}</small></div>{!note.read && <button className="mark-read" onClick={() => onRead(i)}>Mark as read</button>}</div>)}</div></Panel><div className="notification-preferences"><span>⚙</span><p>Choose which security events you hear about.</p><button>Notification preferences →</button></div></>; }
function Settings({ dark, setDark, onSave }) { return <><PageHeading title="Settings" description="Personalize your P.R.I.S.M experience and account security." action={<button className="button primary" onClick={onSave}>Save preferences</button>} /><div className="settings-layout"><Panel title="Profile settings" subtitle="How your account appears"><SettingsRow icon="◎" title="Profile information" detail="Name, username, and contact details" action="Edit" /><SettingsRow icon="✉" title="Email address" detail="alex.morgan@prism.id · Verified" action="Update" /></Panel><Panel title="Password & authentication" subtitle="Manage how you sign in"><SettingsRow icon="⌑" title="Authentication methods" detail="2 methods configured" action="Manage" /><SettingsRow icon="⟲" title="Recovery options" detail="Recovery email and backup codes" action="Review" /></Panel><Panel title="Notification preferences" subtitle="Choose which updates you receive"><ToggleRow title="Security alerts" detail="New sign-ins, device changes, and key events" checked /><ToggleRow title="Product updates" detail="Tips and updates about P.R.I.S.M" checked={false} /></Panel><Panel title="Appearance" subtitle="Choose your display preference"><div className="theme-choice"><button className={dark ? "chosen" : ""} onClick={() => setDark(true)}>◐ Dark</button><button className={!dark ? "chosen" : ""} onClick={() => setDark(false)}>☼ Light</button><span>Theme applies across this device.</span></div></Panel><Panel title="Session preferences" subtitle="Choose how long you stay signed in"><SettingsRow icon="◷" title="Session timeout" detail="Sessions expire after 30 days of inactivity" action="Change" /></Panel><Panel title="Account settings" subtitle="Manage your P.R.I.S.M account"><SettingsRow icon="⇩" title="Download your data" detail="Export a copy of your account information" action="Request" /><SettingsRow icon="⊗" title="Close account" detail="Permanently remove your account and data" action="Manage" danger /></Panel></div></>; }
function SettingsRow({ icon, title, detail, action, danger }) { return <div className="settings-row"><span className="settings-icon">{icon}</span><span className="settings-row-copy"><b>{title}</b><small>{detail}</small></span><button className={`text-action ${danger ? "danger-text" : ""}`}>{action} <span>→</span></button></div>; }
function ToggleRow({ title, detail, checked }) { const [enabled, setEnabled] = useState(checked); return <div className="settings-row"><span className="settings-row-copy"><b>{title}</b><small>{detail}</small></span><button role="switch" aria-checked={enabled} className={`toggle ${enabled ? "on" : ""}`} onClick={() => setEnabled(!enabled)}><i /></button></div>; }
function Help({ onContact }) { const [open, setOpen] = useState(0); return <><PageHeading eyebrow="WE'RE HERE TO HELP" title="Help & support" description="Find answers, learn about security, or talk to our team." /><div className="help-cards"><button className="help-card" onClick={() => setOpen(0)}><span className="help-card-icon purple">✦</span><b>About P.R.I.S.M</b><p>Identity security built for the post-quantum era.</p><span>Explore P.R.I.S.M →</span></button><button className="help-card" onClick={() => setOpen(1)}><span className="help-card-icon blue">⌑</span><b>Security guidelines</b><p>Simple steps to keep your digital identity safe.</p><span>Read the guide →</span></button><button className="help-card" onClick={onContact}><span className="help-card-icon green">✉</span><b>Contact support</b><p>Get help from our identity security specialists.</p><span>Get in touch →</span></button><button className="help-card" onClick={onContact}><span className="help-card-icon amber">⚑</span><b>Report a security issue</b><p>Tell us about suspicious activity or a vulnerability.</p><span>Report an issue →</span></button></div><Panel title="Frequently asked questions" subtitle="Quick answers to common questions"><div className="faq-list">{[["What is P.R.I.S.M?", "P.R.I.S.M is a post-quantum resilient identity and security management platform. It helps you control your identity, devices, and connected services."], ["How do security keys protect my account?", "Your cryptographic key verifies your identity without exposing private key material. P.R.I.S.M supports post-quantum algorithms including ML-KEM, ML-DSA, and SLH-DSA."], ["How do I remove a connected application?", "Open Access Permissions, find the application, and select Revoke. The application will no longer be able to access your identity."], ["What should I do if I see a suspicious sign-in?", "Revoke any unfamiliar device, terminate sessions you do not recognize, and report the event to our security team."]].map(([q, a], i) => <button className={`faq-row ${open === i ? "opened" : ""}`} key={q} onClick={() => setOpen(open === i ? -1 : i)}><span><b>{q}</b>{open === i && <p>{a}</p>}</span><i>{open === i ? "−" : "+"}</i></button>)}</div></Panel><div className="support-bar"><span>◉</span><div><b>Need a hand?</b><small>Our support team is available around the clock.</small></div><button className="button primary" onClick={onContact}>Contact support <span>→</span></button></div></>; }
