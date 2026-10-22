#!/usr/bin/env python3
"""Generate the documentation diagrams as SVG, in English and Russian.

    python3 docs/assets/generate.py

Every diagram is produced from this file, so a wording fix is a one-line
change and both languages stay in step. Output is plain SVG with an
explicit light background, which renders identically on GitHub in light
and dark themes and stays sharp at any zoom.

Layout is computed, not hand-placed: every string is measured against real
font metrics (the table below), wrapped to the box it has to live in, and
boxes grow to fit their content. That is what keeps the Russian set, whose
strings run 15-30% longer, inside the same frames as the English one.
"""

import os
import random

# --------------------------------------------------------------- metrics
# Advance widths in 1/1000 em, measured from DejaVu Sans / DejaVu Sans Bold,
# which is what a plain "sans-serif" resolves to on a Linux renderer. DejaVu
# is wider than Helvetica, Arial and Segoe UI, so a layout that fits here fits
# everywhere the diagrams are actually viewed.
_CH = (" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~«°±»×ЀЁЂЃЄЅІЇЈЉЊЋЌЍЎЏАБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯабвгдежзийклмнопрстуфхцчшщъыьэюяѐёђѓєѕіїјљњћќѝўџ–—‖‘’“”•…№←→")

_WR = [
    318,401,460,838,636,950,780,275,390,390,500,838,318,361,318,337,636,636,636,636,636,636,636,
    636,636,636,337,337,838,838,838,531,1000,684,686,698,770,632,575,775,752,295,295,656,557,863,
    748,787,603,787,695,635,611,732,684,989,685,611,685,390,337,390,838,500,500,613,635,550,635,
    615,352,635,634,278,278,579,278,974,634,612,635,635,411,521,392,634,592,818,592,592,525,636,
    337,636,838,612,500,838,612,838,632,632,786,610,698,635,295,295,295,1094,1045,786,710,748,
    609,752,684,686,686,610,781,632,1077,641,748,748,710,752,863,752,787,752,603,698,611,609,861,
    685,776,686,1069,1094,832,882,686,698,1080,695,613,617,589,525,691,615,901,532,650,650,604,
    639,754,654,612,654,635,550,582,592,855,592,681,591,915,942,706,790,589,549,842,602,615,615,
    625,525,549,521,278,278,278,902,898,652,604,650,592,654,500,1000,500,318,318,518,518,590,
    1000,1040,838,838]

_WB = [
    348,456,521,838,696,1002,872,306,457,457,523,838,380,415,380,365,696,696,696,696,696,696,696,
    696,696,696,400,400,838,838,838,580,1000,774,762,734,830,683,683,821,837,372,372,775,637,995,
    837,850,733,850,770,720,682,812,774,1103,771,724,725,457,365,457,838,500,500,675,716,593,716,
    678,435,716,712,343,343,665,343,1042,712,687,716,716,493,595,478,712,652,924,645,652,582,712,
    365,712,838,646,500,838,646,838,683,683,878,637,734,720,372,372,372,1154,1130,878,817,837,
    771,837,774,762,762,637,891,683,1224,710,837,837,817,831,995,837,850,837,733,734,682,771,992,
    771,928,808,1235,1326,940,1036,762,734,1174,770,675,698,633,522,808,678,995,581,701,701,679,
    732,817,691,687,691,716,593,580,652,992,645,741,686,1062,1106,752,904,632,593,972,642,678,
    678,714,522,593,595,343,343,343,991,956,734,679,701,652,691,500,1000,500,380,380,657,657,639,
    1000,1203,838,838]

_MONO_ADV = 0.6021  # DejaVu Sans Mono is monospaced
_IDX = {c: i for i, c in enumerate(_CH)}
_ENT = (("&lt;", "<"), ("&gt;", ">"), ("&amp;", "&"))

W = 1180
M = 44                      # page margin
CW = W - 2 * M              # usable content width
BG, FG, MUT, LINE, CARD = "#fbfbfd", "#16181d", "#6b7280", "#d9dde3", "#ffffff"
BLUE, GREEN, RED, AMBER, PURPLE, TEAL, GREY = (
    "#2f6feb", "#1f9d63", "#d1495b", "#b7791f", "#6b46c1", "#0f766e", "#8a93a0")
FONT = "-apple-system, BlinkMacSystemFont, Segoe UI, Roboto, Helvetica, Arial, sans-serif"
MONO = "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace"

HERE = os.path.dirname(os.path.abspath(__file__))


def _plain(s):
    for a, b in _ENT:
        s = s.replace(a, b)
    return s


def tw(s, size, bold=False, mono=False):
    """Width of a string in px, from real advance widths."""
    s = _plain(s)
    if mono:
        return len(s) * _MONO_ADV * size
    tbl = _WB if bold else _WR
    total = 0
    for ch in s:
        i = _IDX.get(ch)
        total += tbl[i] if i is not None else 640
    return total * size / 1000.0


def wrap(s, size, maxw, bold=False, mono=False, first=0.0):
    """Greedy word wrap. `first` shortens the first line (for hanging bullets)."""
    lines, cur = [], ""
    for word in s.split():
        cand = word if not cur else cur + " " + word
        limit = maxw - (first if not lines else 0.0)
        if tw(cand, size, bold, mono) <= limit or not cur:
            cur = cand
        else:
            lines.append(cur)
            cur = word
    if cur:
        lines.append(cur)
    return lines


def txt(x, y, s, size=13, fill=MUT, bold=False, anchor=None, mono=False):
    a = f' text-anchor="{anchor}"' if anchor else ""
    b = ' font-weight="700"' if bold else ""
    f = f' font-family="{MONO}"' if mono else ""
    return (f'<text x="{x:.1f}" y="{y:.1f}" font-size="{size}" fill="{fill}"'
            f'{b}{a}{f}>{s}</text>')


def para(x, y, s, size, maxw, fill=MUT, bold=False, lh=None, anchor=None,
         mono=False, bullet=False):
    """Wrapped paragraph. Returns (svg, y of the line after the last one)."""
    lh = lh or round(size * 1.42)
    ind = tw("• ", size) if bullet else 0.0
    lines = wrap(s, size, maxw - ind, bold, mono)
    out = []
    for i, ln in enumerate(lines):
        if bullet:
            out.append(txt(x if i == 0 else x + ind,
                           y, ("• " + ln) if i == 0 else ln,
                           size, fill, bold, anchor, mono))
        else:
            out.append(txt(x, y, ln, size, fill, bold, anchor, mono))
        y += lh
    return "".join(out), y


def para_h(s, size, maxw, lh=None, bold=False, mono=False, bullet=False):
    """Height a paragraph will occupy (line count x line height)."""
    lh = lh or round(size * 1.42)
    ind = tw("• ", size) if bullet else 0.0
    return len(wrap(s, size, maxw - ind, bold, mono)) * lh


def card(x, y, w, h, fill=CARD, stroke=LINE, r=12, op=None):
    o = f' stroke-opacity="{op}"' if op else ""
    return (f'<rect x="{x:.1f}" y="{y:.1f}" width="{w:.1f}" height="{h:.1f}" '
            f'fill="{fill}" stroke="{stroke}"{o} rx="{r}"/>')


def arrow(x1, y1, x2, y2, color=MUT, width=1.4, both=False):
    s = f' marker-start="url(#ar{color[1:]})"' if both else ""
    return (f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" '
            f'stroke="{color}" stroke-width="{width}" '
            f'marker-end="url(#ar{color[1:]})"{s}/>')


_ARROW_COLORS = (MUT, BLUE, GREEN, RED)


def head(title, sub):
    """Page title block. Returns (svg, y where content may start)."""
    out = [txt(M, 52, title, 26, FG, bold=True)]
    body, y = para(M, 80, sub, 15, CW, MUT, lh=21)
    out.append(body)
    return "".join(out), y + 12


def page(h, body):
    defs = "".join(
        f'<marker id="ar{c[1:]}" viewBox="0 0 10 10" refX="9" refY="5" '
        f'markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
        f'<path d="M 0 0 L 10 5 L 0 10 z" fill="{c}"/></marker>'
        for c in _ARROW_COLORS)
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{h:.0f}" '
            f'viewBox="0 0 {W} {h:.0f}" font-family="{FONT}">'
            f'<defs>{defs}</defs>'
            f'<rect width="{W}" height="{h:.0f}" fill="{BG}"/>'
            f'{body}</svg>')


# --------------------------------------------------------------- diagram 1

def d1(L):
    random.seed(20260903)
    hd, top = head(L["d1_title"], L["d1_sub"])
    parts, PAD, CH = [hd], 26, 100
    axw = max(tw(L["d1_axis1"], 11), tw(L["d1_axis2"], 11))
    X0, XE = M + PAD + axw + 24, M + CW - PAD

    def flat():
        out, x = [], X0
        while x < XE - 3:
            out.append((x, random.uniform(0.94, 1.0)))
            x += 4
        return out

    def bursty():
        out, x = [], X0
        while x < XE - 3:
            for _ in range(random.randint(6, 22)):
                r = random.random()
                out.append((x, random.uniform(0.03, 0.10) if r < 0.30 else
                            random.uniform(0.12, 0.35) if r < 0.55 else
                            random.uniform(0.35, 0.65) if r < 0.80 else
                            random.uniform(0.65, 1.0)))
                x += 4
                if x >= XE - 3:
                    break
            x += random.uniform(14, 46)
        return out

    rows = [(L["d1_r1"], L["d1_r1s"], RED, flat),
            (L["d1_r2"], L["d1_r2s"], GREY, bursty),
            (L["d1_r3"], L["d1_r3s"], GREEN, bursty)]

    y = top
    for title, sub, color, gen in rows:
        sub_svg, after = para(M + PAD, y + 60, sub, 13, CW - 2 * PAD, MUT, lh=18)
        ctop = after + 10
        base = ctop + CH
        bars = "".join(
            f'<rect x="{bx:.1f}" y="{base - h * CH:.1f}" width="3" '
            f'height="{h * CH:.1f}" fill="{color}" rx="0.6"/>' for bx, h in gen())
        mid = ctop + CH / 2
        parts.append(card(M, y, CW, base + 44 - y, r=10))
        parts.append(txt(M + PAD, y + 34, title, 16, FG, bold=True))
        parts.append(sub_svg)
        parts.append(txt(M + PAD, mid - 3, L["d1_axis1"], 11))
        parts.append(txt(M + PAD, mid + 13, L["d1_axis2"], 11))
        parts.append(f'<line x1="{X0}" y1="{base + 1:.1f}" x2="{XE}" '
                     f'y2="{base + 1:.1f}" stroke="{LINE}"/>')
        parts.append(bars)
        parts.append(txt(XE, base + 24, L["time"], 11, anchor="end"))
        y = base + 44 + 26

    foot, y = para(M, y + 10, L["d1_foot"], 14, CW, FG, lh=20)
    parts.append(foot)
    return page(y + 18, "".join(parts))


# --------------------------------------------------------------- diagram 2

def _stack(x, w, heading, rows, top, target=None, gap_min=18):
    """A titled column of stacked boxes joined by arrows. Returns (svg, height).

    When a target height is given, the surplus goes into the boxes themselves
    (text stays vertically centred) rather than into ever longer arrows, so two
    columns with a different number of steps still look deliberate."""
    bw = w - 40
    inner = bw - 32
    ch = [18 + para_h(s, 12, inner, lh=17) for _, s, _, _ in rows]
    base = [c + 26 for c in ch]
    n = len(rows)
    natural = 62 + sum(base) + (n - 1) * gap_min + 24
    extra = max(0.0, (target or 0) - natural)
    grow = extra * 0.62 / n
    gap = gap_min + (extra * 0.38 / (n - 1) if n > 1 else 0)
    h = max(natural, target or 0)
    out = [card(x, top, w, h),
           txt(x + 24, top + 38, heading, 17, FG, bold=True)]
    ry = top + 62
    for i, ((t, sub, fill, stroke), c) in enumerate(zip(rows, ch)):
        rh = base[i] + grow
        off = (rh - c) / 2
        out.append(card(x + 20, ry, bw, rh, fill, stroke, r=8,
                        op=0.6 if stroke != LINE else None))
        out.append(txt(x + 36, ry + off + 15, t, 14, FG, bold=True))
        body, _ = para(x + 36, ry + off + 31, sub, 12, inner, MUT, lh=17)
        out.append(body)
        if i < n - 1:
            out.append(arrow(x + w / 2, ry + rh + 4, x + w / 2, ry + rh + gap - 4))
        ry += rh + gap
    return "".join(out), h


def d2(L):
    hd, top = head(L["d2_title"], L["d2_sub"])
    parts = [hd]
    cw1, cw2 = 356, 300
    cw3 = CW - cw1 - cw2 - 80
    x1, x2, x3 = M, M + cw1 + 40, M + cw1 + cw2 + 80

    client = [(t, s, "#f4f6fa", LINE) for t, s in L["d2_layers"]]
    server = []
    for t, s, kind in L["d2_server"]:
        fill = {"yes": "#f0fbf5", "no": "#f1f6ff"}.get(kind, "#f4f6fa")
        server.append((t, s, fill, {"yes": GREEN, "no": BLUE}.get(kind, LINE)))

    _, h1 = _stack(x1, cw1, L["client"], client, top)
    _, h3 = _stack(x3, cw3, L["server"], server, top)

    # censor panel: natural height, then padded out so it sits in scale with
    # the two columns instead of floating as a small box in a wide gap.
    inner = cw2 - 36
    bullets = [para_h(b, 12.5, inner, lh=18, bullet=True) for b in L["d2_sees"]]
    last = para_h(L["d2_cannot1"], 12.5, inner, lh=18, bullet=True)
    fixed = 34 + 28 + 26 + sum(bullets) + 16 + 26 + last + 22
    slots = len(bullets) + 1

    _, h1 = _stack(x1, cw1, L["client"], client, top)
    _, h3 = _stack(x3, cw3, L["server"], server, top)
    H = max(h1, h3, fixed + 60)
    s1, _ = _stack(x1, cw1, L["client"], client, top, H)
    s3, _ = _stack(x3, cw3, L["server"], server, top, H)
    parts += [s1, s3]

    g = min(10.0, max(0.0, (H - 96 - fixed) / slots))
    ch = fixed + slots * g
    ctop = top + (H - ch) / 2
    parts.append(card(x2, ctop, cw2, ch, "#fff7ed", AMBER, op=0.45))
    parts.append(txt(x2 + cw2 / 2, ctop + 34, L["d2_censor"], 15, AMBER,
                     bold=True, anchor="middle"))
    yy = ctop + 62 + g
    parts.append(txt(x2 + 18, yy, L["d2_cansee"], 12.5, FG, bold=True))
    yy += 26
    for b in L["d2_sees"]:
        blk, yy = para(x2 + 18, yy, b, 12.5, inner, MUT, lh=18, bullet=True)
        parts.append(blk)
        yy += g
    yy += 16
    parts.append(txt(x2 + 18, yy, L["d2_cannot"], 12.5, FG, bold=True))
    yy += 26
    blk, yy = para(x2 + 18, yy, L["d2_cannot1"], 12.5, inner, MUT, lh=18, bullet=True)
    parts.append(blk)

    my = top + H / 2
    parts.append(arrow(x1 + cw1 + 8, my, x2 - 8, my, MUT, 2))
    parts.append(arrow(x2 + cw2 + 8, my, x3 - 8, my, MUT, 2))

    fy = top + H + 34
    fh = 30 + para_h(L["d2_point_body"], 13, CW - 52, lh=19) + 22
    parts.append(card(M, fy, CW, fh, r=10))
    parts.append(txt(M + 26, fy + 30, L["d2_point"], 14, FG, bold=True))
    blk, _ = para(M + 26, fy + 52, L["d2_point_body"], 13, CW - 52, MUT, lh=19)
    parts.append(blk)
    return page(fy + fh + 34, "".join(parts))


# --------------------------------------------------------------- diagram 3

def d3(L):
    hd, top = head(L["d3_title"], L["d3_sub"])
    CX, SX = 210, 970
    MID = (CX + SX) / 2
    TXTW = SX - CX - 60   # keeps 30px clear of both lifelines
    BADGE = 76
    parts = [hd]
    life_top = top + 46
    parts.append(card(CX - 100, top, 200, 46, r=9))
    parts.append(txt(CX, top + 30, L["client"], 15, FG, bold=True, anchor="middle"))
    parts.append(card(SX - 100, top, 200, 46, r=9))
    parts.append(txt(SX, top + 30, L["server"], 15, FG, bold=True, anchor="middle"))

    colors = {"c": BLUE, "s": GREEN, "x": RED, "b": GREEN}
    cursor = life_top + 26
    for n, (kind, title, sub) in enumerate(L["d3_steps"], 1):
        if kind == "check":
            pw = min(max(tw(title, 14, True), tw(L["d3_ct"], 11.5)) + 70, TXTW)
            ptop = cursor + 16
            parts.append(card(MID - pw / 2, ptop, pw, 64, "#fffaf0", AMBER, r=9, op=0.55))
            parts.append(txt(MID, ptop + 27, title, 14, FG, bold=True, anchor="middle"))
            parts.append(txt(MID, ptop + 49, L["d3_ct"], 11.5, MUT, anchor="middle"))
            parts.append(f'<circle cx="{BADGE}" cy="{ptop + 32:.1f}" r="15" '
                         f'fill="{CARD}" stroke="{LINE}"/>')
            parts.append(txt(BADGE, ptop + 37, str(n), 12.5, MUT, anchor="middle"))
            blk, cursor = para(MID, ptop + 92, sub, 12.5, TXTW, MUT,
                               lh=17, anchor="middle")
            parts.append(blk)
            cursor += 6
            continue
        tl = wrap(title, 13.5, TXTW, True)
        sl = wrap(sub, 12.5, TXTW)
        y = cursor + 34 + (len(tl) - 1) * 18 + 14
        ty = y - 14 - (len(tl) - 1) * 18
        for ln in tl:
            parts.append(txt(MID, ty, ln, 13.5, FG, bold=True, anchor="middle"))
            ty += 18
        x1, x2 = (CX, SX) if kind in ("c", "b") else (SX, CX)
        parts.append(arrow(x1, y, x2, y, colors[kind], 1.9, both=(kind == "b")))
        parts.append(f'<circle cx="{BADGE}" cy="{y:.1f}" r="15" fill="{CARD}" '
                     f'stroke="{LINE}"/>')
        parts.append(txt(BADGE, y + 5, str(n), 12.5, MUT, anchor="middle"))
        sy = y + 24
        for ln in sl:
            parts.append(txt(MID, sy, ln, 12.5, MUT, anchor="middle"))
            sy += 17
        cursor = sy - 17 + 6

    life_end = cursor + 16
    for lx in (CX, SX):
        parts.append(f'<line x1="{lx}" y1="{life_top}" x2="{lx}" '
                     f'y2="{life_end:.1f}" stroke="{LINE}" stroke-dasharray="4 5"/>')

    fy = life_end + 28
    fh = 22 + para_h(L["d3_foot"], 13.5, CW - 60, lh=20) + 16
    parts.append(card(M, fy, CW, fh, r=10))
    blk, _ = para(W / 2, fy + 32, L["d3_foot"], 13.5, CW - 60, FG, lh=20,
                  anchor="middle")
    parts.append(blk)
    return page(fy + fh + 34, "".join(parts))


# --------------------------------------------------------------- diagram 4

def d4(L):
    hd, top = head(L["d4_title"], L["d4_sub"])
    parts = [hd]
    x0, w0, IN = 60, W - 120, 26
    xs = [x0 + i * IN for i in range(4)]
    ws = [w0 - 2 * i * IN for i in range(4)]

    hdr = []
    for i, (t, s) in enumerate(L["d4_levels"]):
        inner = ws[i] - 36
        h = 26 + (len(wrap(t, 13.5, inner, True)) - 1) * 19
        if s:
            h += para_h(s, 12, inner, lh=17)
        hdr.append(h + 14)

    cells_w = ws[3] - 40
    cw_a = max(150, tw(L["d4_cells"][0][0], 13, True, True) + 44)
    cw_b = max(160, tw(L["d4_cells"][1][0], 13, True, True) + 44)
    cell_ws = [cw_a, cw_b, cells_w - cw_a - cw_b - 12]

    h3 = hdr[3] + 30 + 56 + IN
    h2 = hdr[2] + h3 + IN
    h1 = hdr[1] + h2 + IN
    h_all = [hdr[0] + h1 + IN, h1, h2, h3]

    fills = ["#eef2f7", "#e8f0fe", "#f3eefc", "#e9f7f0"]
    strokes = [LINE, BLUE, PURPLE, GREEN]
    ly = top
    for i, (t, s) in enumerate(L["d4_levels"]):
        inner = ws[i] - 36
        parts.append(card(xs[i], ly, ws[i], h_all[i], fills[i], strokes[i],
                          r=10, op=0.55))
        blk, ny = para(xs[i] + 18, ly + 26, t, 13.5, inner, FG, bold=True, lh=19)
        parts.append(blk)
        if s:
            blk, _ = para(xs[i] + 18, ny, s, 12, inner, MUT, lh=17)
            parts.append(blk)
        ly += hdr[i]

    parts.append(txt(xs[3] + 20, ly + 16, L["d4_be"], 12.5, MUT))
    cx, cy = xs[3] + 20, ly + 30
    for (name, size, fill), cwid in zip(L["d4_cells"], cell_ws):
        parts.append(card(cx, cy, cwid, 56, fill, LINE, r=6))
        parts.append(txt(cx + cwid / 2, cy + 24, name, 13, FG, bold=True,
                         anchor="middle", mono=True))
        parts.append(txt(cx + cwid / 2, cy + 43, size, 11.5, MUT, anchor="middle"))
        cx += cwid + 6

    by = top + h_all[0] + 44
    parts.append(txt(M, by, L["d4_inside"], 17, FG, bold=True))
    by += 18
    half = (CW - 24) / 2
    inner = half - 48
    boxes = [(L["d4_c1t"], L["d4_c1m"], L["d4_c1b"]),
             (L["d4_c2t"], L["d4_c2m"], L["d4_c2b"])]
    bh = max(30 + 26 + 22 + para_h(b, 12.5, inner, lh=18) + 20 for _, _, b in boxes)
    for i, (t, m, b) in enumerate(boxes):
        bx = M + i * (half + 24)
        parts.append(card(bx, by, half, bh, r=10))
        parts.append(txt(bx + 24, by + 32, t, 13.5, FG, bold=True))
        parts.append(txt(bx + 24, by + 58, m, 12.5, TEAL, mono=True))
        blk, _ = para(bx + 24, by + 84, b, 12.5, inner, MUT, lh=18)
        parts.append(blk)

    ty = by + bh + 44
    parts.append(txt(M, ty, L["d4_types"], 17, FG, bold=True))
    ty += 18
    tw3 = (CW - 28) / 3
    inner = tw3 - 28
    th = 22 + max(para_h(d, 11.5, inner, lh=15) for _, _, d in L["d4_stream_types"]) + 14
    for i, (code, name, desc) in enumerate(L["d4_stream_types"]):
        bx = M + (i % 3) * (tw3 + 14)
        byy = ty + (i // 3) * (th + 12)
        parts.append(card(bx, byy, tw3, th, r=7))
        parts.append(txt(bx + 14, byy + 19, code + "  " + name, 12, TEAL,
                         bold=True, mono=True))
        blk, _ = para(bx + 14, byy + 36, desc, 11.5, inner, MUT, lh=15)
        parts.append(blk)
    return page(ty + 2 * th + 12 + 44, "".join(parts))


# --------------------------------------------------------------- diagram 5

def d5(L):
    random.seed(7)
    hd, top = head(L["d5_title"], L["d5_sub"])
    parts = [hd]
    lw, gap = 440, 122
    rw = CW - lw - gap
    lx, rx = M, M + lw + gap

    # ---- left card content, measured
    labw = max(tw(lb, 11.5, mono=True) for lb, _ in L["d5_buckets"])
    pctw = max(tw(f"{int(w * 100)}%", 11) for _, w in L["d5_buckets"])
    bar_x = lx + 24 + labw + 16
    bar_max = (lx + lw - 24) - pctw - 10 - bar_x

    y = top + 34
    left = [txt(lx + 24, y, L["d5_profile"], 17, FG, bold=True)]
    blk, y = para(lx + 24, y + 24, L["d5_profile_sub"], 12.5, lw - 48, MUT, lh=17)
    left.append(blk)
    y += 20
    left.append(txt(lx + 24, y, L["d5_dist"], 13, FG, bold=True))
    y += 20
    for lb, wgt in L["d5_buckets"]:
        bw = bar_max * wgt / max(w for _, w in L["d5_buckets"])
        left.append(txt(lx + 24, y + 12, lb, 11.5, MUT, mono=True))
        left.append(f'<rect x="{bar_x:.1f}" y="{y:.1f}" width="{bw:.1f}" '
                    f'height="16" fill="{BLUE}" opacity="0.78" rx="3"/>')
        left.append(txt(bar_x + bw + 10, y + 12, f"{int(wgt * 100)}%", 11, MUT))
        y += 30
    y += 12
    for headline, lines in ((L["d5_burst"], (L["d5_b1"], L["d5_b2"], L["d5_b3"])),
                            (L["d5_session"], (L["d5_s1"], L["d5_s2"]))):
        left.append(txt(lx + 24, y, headline, 13, FG, bold=True))
        y += 22
        for ln in lines:
            left.append(txt(lx + 24, y, ln, 12, MUT, mono=True))
            y += 19
        y += 12
    lh_nat = y - top + 8

    # ---- right card content, chart height absorbs the difference
    rin = rw - 48
    check_h = 22 + para_h(L["d5_check_body"], 12.5, rin, lh=18)
    fixed = 34 + 24 + 20 + 24 + 40 + check_h + 24
    chart_h = max(120, lh_nat - fixed)
    rh_nat = fixed + chart_h
    H = max(lh_nat, rh_nat)
    chart_h += H - rh_nat

    parts.append(card(lx, top, lw, H))
    parts += left
    parts.append(card(rx, top, rw, H))
    y = top + 34
    parts.append(txt(rx + 24, y, L["d5_output"], 17, FG, bold=True))
    blk, y = para(rx + 24, y + 24, L["d5_output_sub"], 12.5, rin, MUT, lh=17)
    parts.append(blk)
    ctop = y + 16
    X0, XE = rx + 24, rx + rw - 24
    base = ctop + chart_h
    bars, x = [], X0
    while x < XE - 3:
        for _ in range(random.randint(10, 26)):
            r = random.random()
            bars.append((x, random.uniform(0.03, 0.10) if r < 0.05 else
                         random.uniform(0.14, 0.32) if r < 0.15 else
                         random.uniform(0.32, 0.62) if r < 0.40 else
                         random.uniform(0.66, 1.0)))
            x += 4.2
            if x >= XE - 3:
                break
        x += random.uniform(10, 26)
    parts.append("".join(
        f'<rect x="{bx:.1f}" y="{base - h * chart_h:.1f}" width="3" '
        f'height="{h * chart_h:.1f}" fill="{GREEN}" rx="0.6"/>' for bx, h in bars))
    parts.append(f'<line x1="{X0}" y1="{base + 1:.1f}" x2="{XE}" '
                 f'y2="{base + 1:.1f}" stroke="{LINE}"/>')
    parts.append(txt(XE, base + 22, L["time"], 11, anchor="end"))
    parts.append(txt(rx + 24, base + 62, L["d5_check"], 13, FG, bold=True))
    blk, _ = para(rx + 24, base + 84, L["d5_check_body"], 12.5, rin, MUT, lh=18)
    parts.append(blk)

    ay = top + H / 2
    parts.append(arrow(lx + lw + 22, ay, rx - 22, ay, MUT, 2))
    amid = (lx + lw + rx) / 2
    parts.append(txt(amid, ay - 14, L["d5_shaper"], 12.5, FG, bold=True,
                     anchor="middle"))
    parts.append(txt(amid, ay + 26, L["d5_shaper1"], 11.5, MUT, anchor="middle"))
    parts.append(txt(amid, ay + 42, L["d5_shaper2"], 11.5, MUT, anchor="middle"))

    wy = top + H + 34
    wh = 30 + para_h(L["d5_why_body"], 13, CW - 52, lh=19) + 22
    parts.append(card(M, wy, CW, wh, "#fff7ed", AMBER, r=10, op=0.45))
    parts.append(txt(M + 26, wy + 32, L["d5_why"], 14, FG, bold=True))
    blk, _ = para(M + 26, wy + 54, L["d5_why_body"], 13, CW - 52, MUT, lh=19)
    parts.append(blk)
    return page(wy + wh + 34, "".join(parts))


EN = {
 "time": "time →", "client": "Client", "server": "Server",

 "d1_title": "What the censor actually looks at",
 "d1_sub": "Every bar is one TLS record: height is its size, position is when it was sent. All three streams are encrypted.",
 "d1_r1": "A plain VPN under load",
 "d1_r1s": "WireGuard, Shadowsocks, OpenVPN. The payload is encrypted, the shape is not.",
 "d1_r2": "A person using a web application",
 "d1_r2s": "Bursts of mixed record sizes, idle gaps while they read.",
 "d1_r3": "Chamele0nX carrying the same VPN traffic",
 "d1_r3s": "The same bytes as the top row, reshaped to the distribution of the middle row.",
 "d1_axis1": "record", "d1_axis2": "size",
 "d1_foot": "A classifier separates the top row from the middle one without decrypting anything. The bottom row is what this project produces.",

 "d2_title": "How a request travels",
 "d2_sub": "The same connection is a working website and a VPN tunnel. Which one you get depends on whether you hold the secret.",
 "d2_layers": [("Application", "browser, messenger, anything"),
               ("SOCKS5 or packet tunnel", "TCP and UDP are both accepted"),
               ("Multiplexer", "many logical streams inside one tunnel"),
               ("Encryption", "X25519 exchange, then AES-256-GCM per frame"),
               ("Cover", "frames ride inside an HTTP/2 POST to a real API path"),
               ("Record shaping", "sizes and pauses drawn from a traffic profile"),
               ("uTLS", "byte-exact Chrome TLS handshake")],
 "d2_censor": "The censor, in the middle",
 "d2_cansee": "What it can see:",
 "d2_sees": ["a TLS 1.3 connection to a real domain with a valid certificate",
             "a Chrome handshake fingerprint",
             "record sizes and pauses that match ordinary web browsing"],
 "d2_cannot": "What it cannot see:",
 "d2_cannot1": "that any of this is a tunnel",
 "d2_server": [("TLS termination", "port 443, a real certificate for a real domain", ""),
               ("Is there a valid session cookie?", "HMAC over a 5-minute time bucket, checked in constant time", ""),
               ("No: serve the website", "static site, ordinary responses, ordinary 404s", "no"),
               ("Yes: serve the tunnel", "decrypt, demultiplex, open TCP and UDP to the internet", "yes")],
 "d2_point": "The point",
 "d2_point_body": "An active prober that connects without the secret is not refused and not redirected. It is served the website, because the website is genuinely there.",

 "d3_title": "Connecting, step by step",
 "d3_sub": "There is no login screen and no handshake of our own before TLS. Everything up to the cookie check is an ordinary HTTPS page load.",
 "d3_ct": "constant-time HMAC comparison",
 "d3_steps": [
   ("c", "TCP connect to port 443", "nothing unusual: this is the port every website uses"),
   ("c", "TLS ClientHello", "produced by uTLS, byte-identical to a real Chrome handshake; the SNI is the real domain"),
   ("s", "ServerHello and certificate", "a genuine certificate for a genuine domain, issued by a public CA"),
   ("c", "HTTP/2 POST /api/v1/events", "Cookie: wordpress_logged_in_&lt;hash&gt;=&lt;token&gt; — header order and User-Agent copied from Chrome"),
   ("check", "the server checks the cookie", "HMAC-SHA256(secret, 5-minute bucket ‖ server id), compared in constant time"),
   ("x", "no valid cookie: the website", "static files, real 200s and real 404s; the connection ends as an ordinary page view"),
   ("s", "valid cookie: 200, body left open", "the response body becomes the server-to-client half of the tunnel"),
   ("c", "key exchange frame, X25519 public key", "32 bytes on the request body, which is the client-to-server half"),
   ("s", "key exchange frame, X25519 public key", "both sides derive HKDF-SHA256(shared secret, chameleon-session-v1) into an AES-256-GCM key"),
   ("b", "encrypted data frames", "each frame carries multiplexed streams; every TLS record is sized and paced from the profile")],
 "d3_foot": "The cookie rotates every five minutes and the previous window is still accepted, so a captured one is replayable for about ten minutes. A wrong one costs exactly as much time as a right one.",

 "d4_title": "What is inside one byte on the wire",
 "d4_sub": "Five layers of wrapping. Only the outermost one is visible to anyone watching the connection.",
 "d4_levels": [("TCP segment on port 443", ""),
               ("TLS 1.3 record — size and timing chosen by the shaping profile, never a fixed 16 KB", ""),
               ("HTTP/2 DATA frame on an open POST body", "the request body carries client to server, the response body carries server to client"),
               ("Chamele0nX frame", "")],
 "d4_cells": [("type", "2 bytes", "#dbe7ff"), ("length", "4 bytes", "#dbe7ff"), ("payload", "up to 64 KB", "#cdebdd")],
 "d4_be": "big-endian, written as a single write:",
 "d4_inside": "Inside a data frame",
 "d4_c1t": "payload of a data frame",
 "d4_c1m": "nonce (12 B) ‖ AES-256-GCM ciphertext ‖ tag",
 "d4_c1b": "the key comes from the X25519 exchange, lives only in memory, and is wiped when the tunnel closes",
 "d4_c2t": "once decrypted: a multiplexer frame",
 "d4_c2m": "stream id (4 B) ‖ stream type (1 B) ‖ data",
 "d4_c2b": "many application connections share one tunnel, so a single TLS session is all a censor ever sees",
 "d4_types": "Stream types",
 "d4_stream_types": [("0x01", "CONNECT", "open a TCP stream to host and port"),
                     ("0x02", "DATA", "bytes for an open stream"),
                     ("0x03", "FIN", "this side is done sending"),
                     ("0x04", "RST", "the stream failed"),
                     ("0x05", "CONNECT_UDP", "open a UDP association"),
                     ("0x06", "DATAGRAM", "one frame is exactly one UDP datagram")],

 "d5_title": "How a profile becomes traffic",
 "d5_sub": "A profile describes what a real site looks like on the wire. The shaper draws from it instead of writing whatever is convenient.",
 "d5_profile": "The profile",
 "d5_profile_sub": "measured from a real site with chamele0nx-profiler",
 "d5_dist": "record size distribution",
 "d5_buckets": [("128 B – 1.1 KB", 0.08), ("1.1 – 3.4 KB", 0.14), ("3.4 – 9.2 KB", 0.27), ("9.2 – 15.6 KB", 0.51)],
 "d5_burst": "burst pattern",
 "d5_b1": "34–76 records per burst",
 "d5_b2": "4–22 ms pause between bursts",
 "d5_b3": "0–2 ms between records",
 "d5_session": "session shape (recorded, not yet enforced)",
 "d5_s1": "upload : download about 1 : 20",
 "d5_s2": "2–7 concurrent streams",
 "d5_shaper": "shaper",
 "d5_shaper1": "splits and",
 "d5_shaper2": "paces writes",
 "d5_output": "The output",
 "d5_output_sub": "the same VPN bytes, emitted in the shape on the left",
 "d5_check": "Checked, not assumed",
 "d5_check_body": "chamele0nx-validator runs a Kolmogorov-Smirnov test and a chi-squared test on what the shaper produced. Output that fails its own profile is a regression, even when it is faster.",
 "d5_why": "Why real profiles are not shipped in this repository",
 "d5_why_body": "A published profile tells a censor exactly which site to build a classifier against. Capture your own from a site that suits your domain and keep it private. The examples in deploy/profiles were authored for this repository as illustrations, not captured from any site \u2014 running one unmodified gives you the same fingerprint as every other reader.",
}


RU = {
 "time": "время →", "client": "Клиент", "server": "Сервер",

 "d1_title": "На что цензор смотрит на самом деле",
 "d1_sub": "Каждый штрих — одна TLS-запись: высота это её размер, положение — момент отправки. Все три потока зашифрованы.",
 "d1_r1": "Обычный VPN под нагрузкой",
 "d1_r1s": "WireGuard, Shadowsocks, OpenVPN. Содержимое зашифровано, форма — нет.",
 "d1_r2": "Человек работает с веб-приложением",
 "d1_r2s": "Всплески записей разного размера и паузы, пока он читает.",
 "d1_r3": "Chamele0nX везёт тот же самый трафик VPN",
 "d1_r3s": "Те же байты, что в верхней строке, переформованы под распределение из средней.",
 "d1_axis1": "размер", "d1_axis2": "записи",
 "d1_foot": "Классификатор отделяет верхнюю строку от средней, ничего не расшифровывая. Нижняя строка — это то, что выдаёт наш протокол.",

 "d2_title": "Как проходит запрос",
 "d2_sub": "Одно и то же соединение — и работающий сайт, и туннель VPN. Что именно вы получите, зависит от того, есть ли у вас секрет.",
 "d2_layers": [("Приложение", "браузер, мессенджер, что угодно"),
               ("SOCKS5 или пакетный туннель", "принимаются и TCP, и UDP"),
               ("Мультиплексор", "много логических потоков в одном туннеле"),
               ("Шифрование", "обмен X25519, затем AES-256-GCM на каждый кадр"),
               ("Прикрытие", "кадры едут внутри HTTP/2 POST на реальный путь API"),
               ("Формовка записей", "размеры и паузы берутся из профиля трафика"),
               ("uTLS", "побайтово точное рукопожатие Chrome")],
 "d2_censor": "Цензор посередине",
 "d2_cansee": "Что он видит:",
 "d2_sees": ["соединение TLS 1.3 к настоящему домену с действующим сертификатом",
             "отпечаток рукопожатия Chrome",
             "размеры записей и паузы, как при обычном просмотре сайтов"],
 "d2_cannot": "Чего он не видит:",
 "d2_cannot1": "что всё это вообще туннель",
 "d2_server": [("Терминация TLS", "порт 443, настоящий сертификат настоящего домена", ""),
               ("Есть ли верная сессионная кука?", "HMAC по пятиминутному интервалу, проверка за равное время", ""),
               ("Нет: отдаём сайт", "статика, обычные ответы, обычные 404", "no"),
               ("Да: отдаём туннель", "расшифровать, разобрать потоки, открыть TCP и UDP наружу", "yes")],
 "d2_point": "Суть",
 "d2_point_body": "Активная проба, пришедшая без секрета, не получает ни отказа, ни перенаправления. Ей отдают сайт, потому что сайт там действительно есть.",

 "d3_title": "Подключение по шагам",
 "d3_sub": "Нет ни формы входа, ни собственного рукопожатия до TLS. Всё до проверки куки — обычная загрузка HTTPS-страницы.",
 "d3_ct": "сравнение HMAC за равное время",
 "d3_steps": [
   ("c", "TCP-соединение на порт 443", "ничего необычного: этот порт использует любой сайт"),
   ("c", "TLS ClientHello", "сделан через uTLS, побайтово как у настоящего Chrome; в SNI — настоящий домен"),
   ("s", "ServerHello и сертификат", "настоящий сертификат настоящего домена, выданный публичным центром"),
   ("c", "HTTP/2 POST /api/v1/events", "Cookie: wordpress_logged_in_&lt;хеш&gt;=&lt;токен&gt; — порядок заголовков и User-Agent как у Chrome"),
   ("check", "сервер проверяет куку", "HMAC-SHA256(секрет, пятиминутный интервал ‖ идентификатор сервера), сравнение за равное время"),
   ("x", "верной куки нет: отдаётся сайт", "статические файлы, настоящие 200 и настоящие 404; соединение заканчивается как просмотр страницы"),
   ("s", "кука верна: 200, тело ответа не закрывается", "тело ответа становится половиной туннеля от сервера к клиенту"),
   ("c", "кадр обмена ключами, открытый ключ X25519", "32 байта в теле запроса — это половина туннеля от клиента к серверу"),
   ("s", "кадр обмена ключами, открытый ключ X25519", "обе стороны выводят HKDF-SHA256(общий секрет, chameleon-session-v1) в ключ AES-256-GCM"),
   ("b", "зашифрованные кадры данных", "в кадрах едут мультиплексированные потоки; каждой TLS-записи размер и темп задаёт профиль")],
 "d3_foot": "Кука меняется каждые пять минут, а предыдущий интервал ещё принимается, поэтому перехваченная годится примерно десять минут. Неверная обходится ровно во столько же времени, сколько верная.",

 "d4_title": "Что находится внутри байта на проводе",
 "d4_sub": "Пять слоёв обёртки. Снаружи виден только самый внешний.",
 "d4_levels": [("Сегмент TCP на порту 443", ""),
               ("Запись TLS 1.3 — размер и момент выбирает профиль формовки, а не фиксированные 16 КБ", ""),
               ("Кадр HTTP/2 DATA в открытом теле POST", "тело запроса везёт от клиента к серверу, тело ответа — от сервера к клиенту"),
               ("Кадр Chamele0nX", "")],
 "d4_cells": [("тип", "2 байта", "#dbe7ff"), ("длина", "4 байта", "#dbe7ff"), ("нагрузка", "до 64 КБ", "#cdebdd")],
 "d4_be": "старший байт первым, отправляется одной записью:",
 "d4_inside": "Что внутри кадра данных",
 "d4_c1t": "полезная нагрузка кадра данных",
 "d4_c1m": "nonce (12 Б) ‖ шифртекст AES-256-GCM ‖ тег",
 "d4_c1b": "ключ получен из обмена X25519, живёт только в памяти и затирается при закрытии туннеля",
 "d4_c2t": "после расшифровки: кадр мультиплексора",
 "d4_c2m": "id потока (4 Б) ‖ тип потока (1 Б) ‖ данные",
 "d4_c2b": "много соединений приложения делят один туннель, поэтому цензор всегда видит одну TLS-сессию",
 "d4_types": "Типы потоков",
 "d4_stream_types": [("0x01", "CONNECT", "открыть поток TCP на узел и порт"),
                     ("0x02", "DATA", "байты для открытого потока"),
                     ("0x03", "FIN", "эта сторона закончила передачу"),
                     ("0x04", "RST", "поток оборвался с ошибкой"),
                     ("0x05", "CONNECT_UDP", "открыть ассоциацию UDP"),
                     ("0x06", "DATAGRAM", "один кадр — ровно одна датаграмма UDP")],

 "d5_title": "Как профиль превращается в трафик",
 "d5_sub": "Профиль описывает, как настоящий сайт выглядит на проводе. Формовщик берёт размеры оттуда, а не пишет как удобнее.",
 "d5_profile": "Профиль",
 "d5_profile_sub": "снят с настоящего сайта утилитой chamele0nx-profiler",
 "d5_dist": "распределение размеров записей",
 "d5_buckets": [("128 Б – 1,1 КБ", 0.08), ("1,1 – 3,4 КБ", 0.14), ("3,4 – 9,2 КБ", 0.27), ("9,2 – 15,6 КБ", 0.51)],
 "d5_burst": "рисунок всплесков",
 "d5_b1": "34–76 записей во всплеске",
 "d5_b2": "пауза 4–22 мс между всплесками",
 "d5_b3": "0–2 мс между записями",
 "d5_session": "форма сессии (записана, пока не применяется)",
 "d5_s1": "отдача к приёму примерно 1 : 20",
 "d5_s2": "2–7 одновременных потоков",
 "d5_shaper": "формовщик",
 "d5_shaper1": "режет и задаёт",
 "d5_shaper2": "темп записи",
 "d5_output": "Результат",
 "d5_output_sub": "те же байты VPN, выданные в форме, что слева",
 "d5_check": "Проверяется, а не предполагается",
 "d5_check_body": "chamele0nx-validator гоняет критерий Колмогорова — Смирнова и хи-квадрат по тому, что выдал формовщик. Результат, не прошедший собственный профиль, — это регресс, даже если стало быстрее.",
 "d5_why": "Почему настоящие профили не лежат в этом репозитории",
 "d5_why_body": "Опубликованный профиль прямо указывает цензору, против какого сайта строить классификатор. Снимите свой с сайта, подходящего вашему домену, и держите при себе. Примеры в deploy/profiles написаны для этого репозитория как иллюстрации и ни с какого сайта не сняты: запустите такой как есть — получите ту же форму, что и все остальные читатели.",
}


DIAGRAMS = [("01-what-the-censor-sees", d1), ("02-architecture", d2),
            ("03-handshake", d3), ("04-wire-format", d4), ("05-shaping", d5)]

if __name__ == "__main__":
    for lang, L in (("en", EN), ("ru", RU)):
        out = os.path.join(HERE, lang)
        os.makedirs(out, exist_ok=True)
        for name, fn in DIAGRAMS:
            path = os.path.join(out, name + ".svg")
            with open(path, "w") as f:
                f.write(fn(L))
            print("wrote", os.path.relpath(path, HERE))
