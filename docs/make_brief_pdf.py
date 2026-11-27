"""Build docs/PRISM_brief.pdf (exactly two pages) with reportlab.

Needs only for this script: pip install reportlab. It is not a dependency of the product.
Usage: python docs/make_brief_pdf.py [--video URL] [--out docs/PRISM_brief.pdf]
The script fails if the result is not exactly two pages.
"""
from __future__ import annotations

import argparse
import sys

from reportlab.graphics.shapes import Drawing, Line, Polygon, Rect, String
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import BaseDocTemplate, Frame, PageBreak, PageTemplate, Paragraph, Spacer, Table, TableStyle

REPO = "https://github.com/Aditya2375/PRISM"
INK = colors.HexColor("#1b1f24")
ACCENT = colors.HexColor("#1f4e79")
MUTED = colors.HexColor("#5a6470")

body = ParagraphStyle("body", fontName="Helvetica", fontSize=8.4, leading=10.6, textColor=INK, alignment=TA_LEFT, spaceAfter=2.5)
small = ParagraphStyle("small", parent=body, fontSize=7.8, leading=9.6, spaceAfter=1.5)
bullet = ParagraphStyle("bullet", parent=body, leftIndent=9, bulletIndent=0, spaceAfter=1.8)
sbullet = ParagraphStyle("sbullet", parent=small, leftIndent=9, bulletIndent=0, spaceAfter=1.3)
h1 = ParagraphStyle("h1", fontName="Helvetica-Bold", fontSize=15, leading=18, textColor=ACCENT, spaceAfter=1)
sub = ParagraphStyle("sub", parent=body, textColor=MUTED, fontSize=8.2, spaceAfter=5)
h2 = ParagraphStyle("h2", fontName="Helvetica-Bold", fontSize=10, leading=12.5, textColor=ACCENT, spaceBefore=5, spaceAfter=2)
cell = ParagraphStyle("cell", parent=small, spaceAfter=0, fontSize=7.4, leading=9)


def P(t, s=body):
    return Paragraph(t, s)


def B(t, s=bullet):
    return Paragraph(t, s, bulletText="\u2022")


def diagram() -> Drawing:
    W, H = 500, 150
    d = Drawing(W, H)

    def box(x, y, w, h, title, lines, fill):
        d.add(Rect(x, y, w, h, rx=3, ry=3, fillColor=fill, strokeColor=ACCENT, strokeWidth=0.8))
        d.add(String(x + 5, y + h - 11, title, fontName="Helvetica-Bold", fontSize=7.6, fillColor=INK))
        for i, l in enumerate(lines):
            d.add(String(x + 5, y + h - 21 - 8.6 * i, l, fontName="Helvetica", fontSize=6.7, fillColor=INK))

    def arrow(x1, y1, x2, y2, label=None, dy=3):
        d.add(Line(x1, y1, x2, y2, strokeColor=MUTED, strokeWidth=0.9))
        import math
        a = math.atan2(y2 - y1, x2 - x1)
        d.add(Polygon([x2, y2, x2 - 5 * math.cos(a - 0.4), y2 - 5 * math.sin(a - 0.4),
                       x2 - 5 * math.cos(a + 0.4), y2 - 5 * math.sin(a + 0.4)], fillColor=MUTED, strokeColor=MUTED))
        if label:
            d.add(String((x1 + x2) / 2, (y1 + y2) / 2 + dy, label, fontName="Helvetica-Oblique", fontSize=6.3,
                         fillColor=MUTED, textAnchor="middle"))

    light, pale = colors.HexColor("#eaf1f8"), colors.HexColor("#f6f6f2")
    box(0, 70, 128, 76, "Devices (laptop, limited phone)",
        ["ML-DSA-65 signing key", "ML-KEM-768 + X25519 key", "encrypts file: AES-256-GCM", "checks signed manifest,", "pins root and writers"], light)
    box(178, 70, 150, 76, "Primary node (node-a)",
        ["verifies signature, audience,", "nonce, revoked set (read first)", "stores ciphertext + per-device", "wrapped keys, never a key", "signed hash-chained audit log"], light)
    box(378, 96, 122, 50, "Replica node-b", ["signed revocation certificates", "lease: stale = refuses all"], light)
    box(378, 38, 122, 50, "Replica node-c", ["own keys, data, audit log", "separate OS process, TCP"], light)
    box(178, 0, 150, 56, "Evidence and recovery",
        ["signed backups, sealed to an", "offline key (k-of-n split)", "standalone verifier, no keys"], pale)
    box(0, 0, 128, 56, "Operator", ["alerts: rule, device, user,", "node, event, source, evidence", "revoke-device, recover-admin"], pale)
    arrow(128, 108, 178, 108, "signed request", 3)
    arrow(328, 122, 378, 122)
    arrow(328, 92, 378, 70)
    arrow(253, 70, 253, 56)
    arrow(178, 28, 128, 28)
    return d


def header() -> Drawing:
    W = 504
    d = Drawing(W, 44)
    d.add(Polygon([22, 6, 38, 34, 6, 34], fillColor=None, strokeColor=ACCENT, strokeWidth=2.2, strokeLineJoin=1))
    d.add(Line(0, 21, 14, 20, strokeColor=INK, strokeWidth=1.8))
    d.add(Line(30, 22, 44, 27, strokeColor=ACCENT, strokeWidth=1.4))
    d.add(Line(31, 18, 44, 18, strokeColor=ACCENT, strokeWidth=1.4))
    d.add(String(54, 20, "P.R.I.S.M.", fontName="Helvetica-Bold", fontSize=21, fillColor=INK))
    d.add(String(54, 6, "Post-quantum Resilient Identity & Security Management", fontName="Helvetica", fontSize=8.6, fillColor=MUTED))
    d.add(String(W, 22, "DevForge Yugaantar  |  Track 4  |  Trust, but verify", fontName="Helvetica-Bold", fontSize=8, fillColor=ACCENT, textAnchor="end"))
    d.add(String(W, 10, "Team Do You Care  |  MIT  |  Python 3.12 and 3.13", fontName="Helvetica", fontSize=7.6, fillColor=MUTED, textAnchor="end"))
    d.add(Line(0, 0, W, 0, strokeColor=ACCENT, strokeWidth=1))
    return d


def metrics() -> Table:
    big = ParagraphStyle("big", fontName="Helvetica-Bold", fontSize=15, leading=17, textColor=ACCENT)
    lab = ParagraphStyle("lab", fontName="Helvetica", fontSize=6.9, leading=8.3, textColor=MUTED)
    cells = [("0.0", "false alerts per 1,000 benign requests (1,265 replayed)"),
             ("F1 0.91", "precision 1.00, recall 0.83 over 12 labelled scenarios, 2 of them missed on purpose"),
             ("about 25 ms", "median revocation to the last of 3 real node processes (slowest of 20 runs 53 ms); loopback, one clock, one machine"),
             ("30 s | 0 | lease", "grace: rotation | revoked device | cut-off replica (2 s real, 5 s simulated)")]
    t = Table([[Paragraph(a, big) for a, _ in cells], [Paragraph(b, lab) for _, b in cells]], colWidths=[43.5 * mm] * 4)
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f2f6fa")), ("LINEAFTER", (0, 0), (-2, -1), 0.6, colors.white),
                           ("LEFTPADDING", (0, 0), (-1, -1), 6), ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                           ("TOPPADDING", (0, 0), (-1, 0), 5), ("BOTTOMPADDING", (0, 0), (-1, 0), 0),
                           ("TOPPADDING", (0, 1), (-1, 1), 1), ("BOTTOMPADDING", (0, 1), (-1, 1), 5), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    return t


def page1(video: str) -> list:
    f: list = []
    f.append(header())
    f.append(Spacer(1, 6))
    f.append(metrics())
    f.append(P("What it is, and what makes it different", h2))
    f.append(P("One workflow done fully and checked from outside: <b>a user shares an encrypted file across devices, a device is lost, "
               "its access is cut on every node, the file is re-keyed, an alert says who, where and why, and someone who does not "
               "trust the service can verify the record.</b> We chose depth over breadth. Every claim below is tied to a test or a "
               "command that prints the number, and every limit is written next to the claim it limits."))
    f.append(B("<b>Post-quantum from day one, nothing custom.</b> Hybrid ML-KEM-768 + X25519 (HPKE) wraps a fresh AES-256-GCM key per file "
               "version for each eligible device. All signatures are ML-DSA-65. Primitives come from one pinned library; a second vetted "
               "library only splits the backup key k-of-n. NIST known-answer vectors run in the tests."))
    f.append(B("<b>The server cannot quietly change who reads a file.</b> Each version carries a device-signed manifest (access list, owner, key "
               "commitment). Clients check every recipient key against the signed enrolment chain and pin the root, if given its "
               "fingerprint out of band (otherwise trust on first use)."))
    f.append(B("<b>Revocation that fails closed.</b> The revoked set is written first, is union-only, and survives restarts, restores and "
               "rolled-back nodes. Nodes run as three real OS processes over TCP; a node cut off from the primary refuses everyone when its lease ends."))
    f.append(B("<b>Evidence, not assertion.</b> Every decision is a signed, hash-chained audit entry. <i>verifier/prism_verify.py</i> re-checks the "
               "log, a backup or the state with no service code and no private key, and says when completeness is not proven."))
    f.append(P("Architecture", h2))
    f.append(diagram())
    f.append(Spacer(1, 3))
    f.append(P("How it behaves", h2))
    f.append(B("<b>Rotation and crash recovery.</b> A rotation is journalled (prepare, store, commit). Killing the process at any point leaves one "
               "consistent version, no lost revocation and a valid audit chain (crash matrix and random kills over 12 seeds). In-flight reads of the "
               "previous version get a <b>30 s grace</b>, only for devices still eligible; then the node answers <i>key_version_retired</i>."))
    f.append(B("<b>Revocation across nodes.</b> Grace for a revoked device is <b>zero</b>. A replica cut off from the primary can still serve a lost "
               "device until its lease ends (2 s in the real-process harness, 5 s in the in-process simulation), then answers <i>node_stale</i>. "
               "Measured on one machine with three real processes: the last node refused the device after a median 24.8 ms (slowest 53.3 ms, 20 runs) "
               "(<i>python -m kig.demo --net</i>, docs/PERFORMANCE.md). That is loopback and one clock, not a network figure."))
    f.append(B("<b>Powerful devices.</b> A phone is enrolled <i>limited</i> and always acts as a plain member. Removing an admin's device or "
               "disabling an admin needs another admin whose device is at least 15 minutes old. Deleted file ids keep a tombstone."))
    f.append(B("<b>Backup integrity.</b> Backups are signed, sealed to an offline key and streamed. Any flipped byte, truncation, wrong key or "
               "other service's backup is refused and nothing is written; an older valid backup is refused unless waived and audited."))
    f.append(B("<b>Log integrity.</b> Events are JSON lines with a signed chain, so user text cannot start a second event or change the actor. "
               "<i>kig doctor</i> and the verifier fail on any edited line."))
    f.append(P("Detection, measured (<i>python -m kig.bench_detect</i>)", h2))
    f.append(P("Eleven explainable rules, no ML. Replaying 1,265 benign requests raised <b>0 false alerts (0.0 per 1,000)</b>. Twelve labelled attack "
               "scenarios x 20 runs: <b>precision 1.00, recall 0.83, F1 0.91</b>. For the ten scenarios the rules are built for, median time to "
               "alert is 4 to 120 ms wall and 0 to 220 s on the service clock (a flood summary waits one minute by design; slow guessing is "
               "seen after 8 failures in an hour). Two scenarios are "
               "missed on purpose and counted: a denied probe with valid credentials, and a valid insider reading one new file every ten minutes. The scenarios and rules have the same authors, so this describes these traces, not real traffic. "
               "Wall times are from one Linux x86_64 machine and are not portable.", small))
    f.append(P("Cost (<i>python -m kig.bench</i>, median per call on one 1-vCPU machine, docs/PERFORMANCE.md): put 5.8 ms, fetch 2.5 ms, rotate 10.7 ms, "
               "backup of 100 files 62 ms, restore 113 ms.", small))
    return f


def page2(video: str) -> list:
    f: list = [PageBreak()]
    f.append(header())
    f.append(Spacer(1, 4))
    f.append(P("One-page threat model", h1))
    f.append(P("Full version: THREAT_MODEL.md in the repository. Every limit below is stated, not hidden.", sub))
    rows = [
        [P("<b>Protected assets</b>", cell),
         P("File contents; file keys and each device's private keys; the identity directory (users, roles, device status); the audit log (integrity and completeness).", cell)],
        [P("<b>Attackers</b>", cell),
         P("Thief of a lost device (its keys, not the owner's other devices). Network attacker who reads, replays, modifies requests (cannot break TLS or the crypto). "
           "Malicious or compromised member reaching past their access list or toward admin. Insider with database access editing the audit log. "
           "Harvest-now-decrypt-later attacker recording ciphertext and wrapped keys.", cell)],
        [P("<b>Assumptions</b>", cell),
         P("The service host and its data directory are not compromised. Transport is TLS in deployment (the demo binds to localhost; node sync is plain HTTP here). "
           "Device clocks are within 30 s of the service. The two libraries are correct. A root fingerprint reaches clients out of band, otherwise the root is trusted on first use.", cell)],
    ]
    t = Table(rows, colWidths=[24 * mm, 150 * mm])
    t.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LINEBELOW", (0, 0), (-1, -1), 0.4, colors.HexColor("#c9d1d9")),
                           ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3), ("LEFTPADDING", (0, 0), (-1, -1), 2)]))
    f.append(t)
    f.append(P("Controls", h2))
    ctr = [
        ("Lost device keeps working", "Revoked set written first, checked first, only grows. Zero grace on the primary; replicas bounded by their lease, then fail closed. Next authorised read re-keys to a fresh epoch."),
        ("Replay and forgery", "Signature over the whole envelope, signed audience, 30 s window, per-device nonce, requests signed before a restart refused."),
        ("Stolen powerful device", "Limited phones never act as admin. Removing or demoting an admin needs another admin with a device older than 15 minutes. Alert R5 fires when a limited device is removed."),
        ("Audit tampering", "Hash-chained, ML-DSA signed; the service refuses to start on a broken chain or a log shorter than state has seen; the verifier checks it offline."),
        ("Crash mid-rotation or revocation", "Journalled; on restart one consistent version, revocations re-applied, chain valid."),
        ("Damaged or stale backup", "Signed and sealed; any damage is refused with a reason and nothing is written; older backups need an audited waiver."),
        ("Quantum adversary", "Hybrid ML-KEM-768 + X25519 key wrapping; ML-DSA-65 signatures."),
    ]
    rows = [[P(f"<b>{a}</b>", cell), P(b, cell)] for a, b in ctr]
    t = Table(rows, colWidths=[40 * mm, 134 * mm])
    t.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LINEBELOW", (0, 0), (-1, -1), 0.4, colors.HexColor("#c9d1d9")),
                           ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 2), ("LEFTPADDING", (0, 0), (-1, -1), 2)]))
    f.append(t)
    f.append(P("Limits we state", h2))
    for x in [
        "A revoked or lost device keeps everything it already decrypted or copied. Rotation protects later versions only.",
        "The three real node processes share one host, one clock and loopback; timings are not a network measurement. Sync is plain HTTP and needs TLS across hosts; the shared cluster token lets its holder force repeated snapshots.",
        "A stolen full admin device is an admin until the host removes it (<i>kig revoke-device</i>, <i>kig recover-admin</i>). The 15 minute cooling-off uses the service clock.",
        "Rollback of a whole data directory is detected only against a pin kept outside it (<i>KIG_PIN_FILE</i>). The audit log has no independent completeness proof without an external head.",
        "Private keys sit in files (passphrase-sealed when set). Python cannot wipe memory. No hardware key store driver is shipped.",
        "Metadata (file ids, access lists, device ids, access times) is visible to the service. A malicious replica can ignore revocation for clients that talk only to it.",
        "Rule-based detection only: it misses a slow valid insider and denied probes (recall 0.83, up from 0.67 after we tuned rules on our own scenarios). Single worker per data directory.",
        "Alert attribution is a claim, not proof: an alert names a device and user only when an enrolled device failed a signature check, otherwise it says unknown.",
    ]:
        f.append(B(x, sbullet))
    f.append(P("Out of scope, and why", h2))
    for x in [
        "<b>SLH-DSA</b>: ML-DSA-65 alone covers every signature here; a second scheme would add untested code and no claim.",
        "<b>Double Ratchet, PQXDH, forward secrecy</b>: a file key service, not a messenger, no sessions. A stolen device key opens what was wrapped for it.",
        "<b>Session resumption, message loss and reordering</b>: no sessions or message streams; each request is signed on its own.",
        "<b>Merkle log</b>: the audit log is a signed hash chain without inclusion proofs for third parties.",
        "<b>Graph or ATT&amp;CK detection, hybrid logical clocks</b>: eleven rules over audit events. Log lines from other services can be fed in with kig.ingest; an identity reaching new services is flagged, and events from different services within +/-30 s are marked order-uncertain. "
        "There is no graph model, and ordering across services is not proven; a signed request is refused outside +/-30 s.",
    ]:
        f.append(B(x, sbullet))
    f.append(P("Where each claim is checked", h2))
    ev = [("Revocation across nodes, time to last node", "python -m kig.netcluster; tests/test_netcluster.py"),
          ("Crash recovery, revoked stays revoked", "tests/test_crash_and_cutoff.py, tests/test_chaos.py (random kills, 12 seeds)"),
          ("Backup integrity, damage refused", "tests/test_backup.py (200 single-byte flips all refused)"),
          ("Log integrity, offline check", "verifier/prism_verify.py; tests/test_audit.py, tests/test_standalone_verifier.py"),
          ("Detection: F1, time to alert, false alerts", "python -m kig.bench_detect; tests/test_bench_detect.py"),
          ("Cryptography, known answers", "tests/test_crypto_proof.py and NIST vectors in tests/vectors/")]
    t = Table([[P(a, cell), P(f"<i>{b}</i>", cell)] for a, b in ev], colWidths=[66 * mm, 108 * mm])
    t.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LINEBELOW", (0, 0), (-1, -1), 0.4, colors.HexColor("#c9d1d9")),
                           ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 2), ("LEFTPADDING", (0, 0), (-1, -1), 2)]))
    f.append(t)
    f.append(Spacer(1, 5))
    rows = []
    if video:
        rows.append([P(f'<b>Demo video:</b> <link href="{video}" color="#1f4e79"><u>{video}</u></link>', body)])
    rows.append([P(f"<b>Repository:</b> <link href=\"{REPO}\" color=\"#1f4e79\"><u>{REPO}</u></link> "
                   "&nbsp; Run it: <i>python -m kig.demo --story</i>, <i>python -m kig.demo --net</i>, <i>python -m pytest -q</i>", body)])
    t = Table(rows, colWidths=[174 * mm])
    t.setStyle(TableStyle([("BOX", (0, 0), (-1, -1), 0.8, ACCENT), ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#eaf1f8")),
                           ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 2)]))
    f.append(t)
    return f


def build(out: str, video: str) -> int:
    doc = BaseDocTemplate(out, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=14 * mm, bottomMargin=13 * mm,
                          title="P.R.I.S.M. project brief", author="Aditya Kulkarni", subject="DevForge Yugaantar, Track 4")
    frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id="f", leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)

    def footer(c, d):
        c.saveState()
        c.setFont("Helvetica", 7)
        c.setFillColor(MUTED)
        c.drawString(doc.leftMargin, 8 * mm, f"P.R.I.S.M. brief, page {d.page} of 2")
        c.drawRightString(A4[0] - doc.rightMargin, 8 * mm, REPO)
        c.restoreState()

    doc.addPageTemplates([PageTemplate(id="p", frames=[frame], onPage=footer)])
    doc.build(page1(video) + page2(video))
    return doc.page


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--video", default="")
    ap.add_argument("--out", default="docs/PRISM_brief.pdf")
    a = ap.parse_args()
    n = build(a.out, a.video)
    if n != 2:
        print(f"FAILED: {n} pages, need exactly 2", file=sys.stderr)
        sys.exit(1)
    print(f"wrote {a.out}: {n} pages")
