import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Ellipse, FancyBboxPatch, Rectangle, FancyArrowPatch, Polygon
from matplotlib.lines import Line2D

FS = 8.3          # node font size
ZFS = 9.6         # zone title font size
LFS = 7.9         # edge label font size

fig, ax = plt.subplots(figsize=(10.6, 11.6), dpi=200)
ax.set_xlim(-1, 103); ax.set_ylim(0, 100); ax.axis("off")

NAVY = "#0F3B57"; ACCENT = "#1F7A8C"; INK = "#1B2A36"


def zone(x, y, w, h, title, edge, face, dashed=False, title_color=None):
    ax.add_patch(Rectangle((x, y), w, h, facecolor=face, edgecolor=edge,
                           linewidth=1.5, linestyle=(0, (5, 3)) if dashed else "solid",
                           zorder=1))
    ax.text(x + w / 2, y + h - 1.7, title, ha="center", va="top",
            fontsize=ZFS, fontweight="bold", color=title_color or edge, zorder=9,
            bbox=dict(boxstyle="round,pad=0.28", fc=face if face != "#FFFFFF" else "white",
                      ec="none"))


def ell(x, y, label, w=23.5, h=8.4, face="white", edge=INK):
    ax.add_patch(Ellipse((x, y), w, h, facecolor=face, edgecolor=edge,
                         linewidth=1.15, zorder=4))
    ax.text(x, y, label, ha="center", va="center", fontsize=FS, color=INK,
            zorder=6, linespacing=1.45)
    return (x, y, w, h)


def box(x, y, label, w=23.0, h=7.4, face="#DCEAF3", edge=NAVY):
    ax.add_patch(FancyBboxPatch((x - w / 2, y - h / 2), w, h,
                                boxstyle="round,pad=0.25,rounding_size=0.5",
                                facecolor=face, edgecolor=edge, linewidth=1.3, zorder=4))
    ax.text(x, y, label, ha="center", va="center", fontsize=FS, color=INK,
            zorder=6, linespacing=1.45)
    return (x, y, w, h)


def diamond(x, y, label, w=30.0, h=11.0, face="#DCEAF3", edge=NAVY):
    pts = [(x, y + h / 2), (x + w / 2, y), (x, y - h / 2), (x - w / 2, y)]
    ax.add_patch(Polygon(pts, closed=True, facecolor=face, edgecolor=edge,
                         linewidth=1.3, zorder=4))
    ax.text(x, y, label, ha="center", va="center", fontsize=FS, color=INK,
            zorder=6, linespacing=1.45)
    return (x, y, w, h)


def cylinder(x, y, label, w=17.0, h=8.0, face="white", edge=INK):
    body = h - 2.0
    ax.add_patch(Rectangle((x - w / 2, y - body / 2), w, body, facecolor=face,
                           edgecolor="none", zorder=4))
    ax.add_patch(Ellipse((x, y - body / 2), w, 2.4, facecolor=face, edgecolor=edge,
                         linewidth=1.1, zorder=4))
    ax.add_patch(Ellipse((x, y + body / 2), w, 2.4, facecolor=face, edgecolor=edge,
                         linewidth=1.1, zorder=5))
    for sx in (-1, 1):
        ax.add_line(Line2D([x + sx * w / 2, x + sx * w / 2],
                           [y - body / 2, y + body / 2], color=edge, lw=1.1, zorder=5))
    ax.text(x, y + 0.1, label, ha="center", va="center", fontsize=FS - 0.2,
            color=INK, zorder=6, linespacing=1.4)
    return (x, y, w, h)


def arrow(p1, p2, label=None, rad=0.0, lx=None, ly=None, dashed=False,
          color=INK, ha="center"):
    ax.add_patch(FancyArrowPatch(p1, p2, arrowstyle="-|>", mutation_scale=13,
                                 linewidth=1.15, color=color, zorder=3,
                                 linestyle=(0, (4, 2.5)) if dashed else "solid",
                                 connectionstyle=f"arc3,rad={rad}",
                                 shrinkA=1, shrinkB=1))
    if label:
        mx = lx if lx is not None else (p1[0] + p2[0]) / 2
        my = ly if ly is not None else (p1[1] + p2[1]) / 2
        ax.text(mx, my, label, ha=ha, va="center", fontsize=LFS, color=INK,
                zorder=7, linespacing=1.35,
                bbox=dict(boxstyle="round,pad=0.20", fc="white", ec="none", alpha=0.95))


# ───────────────────────────── zones ─────────────────────────────
zone(1.5, 70.5, 53.0, 28.0, "CONTENT & GOVERNANCE LAYER (Scope & Policy)",
     "#7A8794", "#F4F6F8")
zone(58.0, 70.5, 40.5, 28.0, "EXERCISE HOST (Role Workspaces)", "#2E6F9E", "#EAF3FA")
zone(20.0, 24.5, 78.0, 42.5, "EXECUTION GUARDRAILS (Real-time Enforcement)",
     "#C8791E", "#FDF3E4")
zone(26.0, 1.5, 68.0, 18.0, "EMULATION TARGET ESTATE (Isolated Range, No Egress)",
     "#2F8F6B", "#FFFFFF", dashed=True)

# ──────────────────────── governance layer ───────────────────────
ell(15.5, 91.0, "Safety Classification\n(S0 / S1 / S2 / Prohibited)", w=25.0)
ell(42.0, 91.0, "Framework Crosswalks\n(NIST CSF, NICE, CIS, CAE)", w=24.0)
ell(28.5, 77.0, "Signed Scenario &\nModule Catalog\n(What is permitted to run)", w=29.0, h=10.6)
arrow((17.5, 86.9), (24.0, 82.0), rad=-0.12)
arrow((41.0, 86.9), (33.5, 82.2), rad=0.12)

# ────────────────────────── exercise host ────────────────────────
diamond(78.0, 88.8, "Red / Blue / Purple\nRole Workspaces", w=33.0, h=11.6)
box(78.0, 76.0, "Control Plane\n(Lifecycle Orchestrator)", w=26.0, h=8.0)
arrow((73.5, 83.0), (73.5, 80.1), rad=0.0)
arrow((82.5, 80.1), (82.5, 83.0), rad=0.0)
ax.text(72.4, 81.6, "Operator\nIntent", ha="right", va="center", fontsize=LFS,
        color=INK, linespacing=1.3)
ax.text(83.6, 81.6, "Redacted\nView", ha="left", va="center", fontsize=LFS,
        color=INK, linespacing=1.3)

# governance → guardrails, host → guardrails
arrow((28.5, 71.6), (28.5, 60.9), label="Defines Scope", dashed=True, ly=67.4)
arrow((70.5, 71.8), (50.0, 61.2), label="Action Request", rad=0.10, lx=60.5, ly=69.4)

# ──────────────────────────── guardrails ─────────────────────────
ell(37.0, 56.6, "Signature & Safety Gate\n(Unsigned refused,\nProhibited blocked)", w=28.0, h=10.4)
ell(37.0, 43.5, "Isolation Enforcement\n(No egress, no host mounts,\nCPU / memory / PID capped)", w=30.0, h=10.6)
ell(37.0, 29.5, "S2 Approval Gate\n(Instructor / Admin\nhuman-in-the-loop)", w=27.0, h=10.2)
arrow((37.0, 51.3), (37.0, 48.9))
arrow((37.0, 38.1), (37.0, 34.7), label="Safe?", lx=39.6, ha="left")

ell(79.0, 56.6, "Append-Only\nAudit Ledger", w=24.0, h=9.0)
ell(79.0, 43.5, "Detection Engine\n(Versioned Sigma-style\nrules, MTTD)", w=26.0, h=10.6)
ell(79.0, 29.5, "Evidence Timeline\n(UTC, hash-stamped)", w=26.0, h=9.4)
arrow((79.0, 34.3), (79.0, 38.1), label="Correlate", lx=81.6, ha="left")
arrow((79.0, 48.9), (79.0, 52.0), label="Record Outcome", lx=81.6, ha="left")
arrow((84.0, 61.0), (84.0, 71.9), label="Validated Result", rad=-0.10, lx=88.3, ly=67.4)

# ──────────────────────── emulation targets ──────────────────────
cylinder(38.0, 8.9, "Victim Host\n(Persistent\nfoothold)", w=19.0, h=10.2)
box(59.5, 8.9, "Web App Target\n(Reachable over\nrange network)", w=21.0, h=9.6,
    face="#FFFFFF", edge=INK)
box(82.0, 8.9, "LDAP Directory\n(Synthetic\ndomain users)", w=21.0, h=9.6,
    face="#FFFFFF", edge=INK)

arrow((32.0, 25.0), (34.5, 14.2), label="Authorized\nExecution", rad=0.14, lx=24.0, ly=22.2)
arrow((44.5, 25.6), (55.5, 14.0), label="Authorized\nAction", rad=-0.14, lx=52.0, ly=22.0)
arrow((88.5, 14.0), (86.0, 24.7), label="Real stdout, stderr,\nexit code, timing",
      rad=0.14, lx=96.0, ly=19.0, ha="center")

# ────────────────────────────── note ─────────────────────────────
ax.add_patch(Rectangle((1.5, 47.0), 15.0, 13.5, facecolor="white",
                       edgecolor=INK, linewidth=1.0, zorder=4))
ax.text(9.0, 53.7,
        "Governance sets\nWHAT may run.\nGuardrails enforce\nHOW it runs.\n"
        "The emulation tier\nruns it FOR REAL.",
        ha="center", va="center", fontsize=7.8, color=INK, zorder=6, linespacing=1.5)

ax.text(50, 0.1,
        "Figure A-1  |  CyberRange emulation-class reference architecture. "
        "All four layers are mandatory and are supplied as one integrated platform.",
        ha="center", va="bottom", fontsize=7.6, color="#5A6672", style="italic")

fig.subplots_adjust(left=0.005, right=0.995, top=0.995, bottom=0.005)
fig.savefig("appendix_architecture.png", dpi=200, facecolor="white")
print("ok")
