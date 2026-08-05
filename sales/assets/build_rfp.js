const fs = require('fs');
const {
  Document, Packer, Paragraph, TextRun, AlignmentType, PageBreak, HeadingLevel,
  Table, TableRow, TableCell, WidthType, ShadingType, BorderStyle, ImageRun,
  Header, Footer, PageNumber, convertInchesToTwip,
} = require('docx');

const rows = JSON.parse(fs.readFileSync('rows.json', 'utf8'));
const KEEP = rows.filter((r) => Number(r.sl) <= 26);   // 27–31 (roadmap) dropped

const F = 'Calibri';
const NAVY = '0F3B57';
const ACCENT = '1F7A8C';
const INK = '22313D';
const MUTED = '667783';
const RULE = 'D8E1E8';
const TINT = 'EEF3F6';
const GREEN = '1E7A4D';
const W = 10080;                                        // 8.5in − 2×0.75in

const NONE = { style: BorderStyle.NONE, size: 0, color: 'FFFFFF' };
const hair = (color = RULE, size = 2) => ({ style: BorderStyle.SINGLE, size, color });

const t = (text, o = {}) => new TextRun({
  text, font: F, size: o.size || 20, bold: !!o.bold, italics: !!o.italics,
  color: o.color || INK, allCaps: !!o.caps, characterSpacing: o.spacing,
});

const p = (children, o = {}) => new Paragraph({
  alignment: o.align || AlignmentType.LEFT,
  spacing: { before: o.before || 0, after: o.after === undefined ? 140 : o.after, line: o.line || 288 },
  indent: o.indent,
  border: o.border,
  keepNext: o.keepNext,
  children: (Array.isArray(children) ? children : [children])
    .map((c) => (typeof c === 'string' ? t(c, o) : c)),
});

const h1 = (text) => p([t(text, { size: 26, bold: true, color: NAVY })],
  { before: 380, after: 60, keepNext: true });

const h2 = (text) => p([t(text, { size: 21, bold: true, color: ACCENT })],
  { before: 260, after: 90, keepNext: true });

const eyebrow = (text) => p([t(text, { size: 16, bold: true, color: ACCENT, caps: true, spacing: 24 })],
  { after: 60 });

const note = (lead, rest) => p([t(lead, { bold: true, color: NAVY }), t(' ' + rest, { color: INK })],
  { before: 160, after: 120 });

function cell(children, width, o = {}) {
  return new TableCell({
    width: { size: width, type: WidthType.DXA },
    shading: o.fill ? { type: ShadingType.CLEAR, fill: o.fill, color: 'auto' } : undefined,
    margins: { top: o.tight ? 90 : 130, bottom: o.tight ? 90 : 130, left: 130, right: 130 },
    verticalAlign: o.valign || 'top',
    borders: {
      top: o.topRule || NONE,
      bottom: o.bottomRule || hair(),
      left: NONE, right: NONE,
    },
    children: Array.isArray(children) ? children : [children],
  });
}

function table(widths, trs) {
  return new Table({
    columnWidths: widths,
    width: { size: W, type: WidthType.DXA },
    borders: { top: NONE, bottom: NONE, left: NONE, right: NONE,
               insideHorizontal: NONE, insideVertical: NONE },
    rows: trs,
  });
}

function headerRow(widths, labels, aligns = []) {
  return new TableRow({
    tableHeader: true,
    children: labels.map((l, i) => cell(
      p([t(l, { size: 17, bold: true, color: NAVY, caps: true, spacing: 16 })],
        { after: 0, line: 240, align: aligns[i] || AlignmentType.LEFT }),
      widths[i], { fill: TINT, tight: true, bottomRule: hair(NAVY, 8) })),
  });
}

// ─────────────────────────────── title block ───────────────────────────────
const title = [
  eyebrow('Votal  ·  CyberRange'),
  p([t('Technical Capabilities Compliance Matrix', { size: 40, bold: true, color: NAVY })],
    { after: 60 }),
  p([t('Red, Blue and Purple Team Training and Security Control Validation Platform',
       { size: 22, color: MUTED })],
    { after: 140, border: { bottom: { style: BorderStyle.SINGLE, size: 10, color: ACCENT, space: 10 } } }),
  p([t('Version 1.1', { bold: true, color: NAVY, size: 18 }),
     t('     Range class: Emulation', { size: 18, color: MUTED }),
     t('     26 requirements, all compliant', { size: 18, color: MUTED })],
    { before: 120, after: 340 }),
];

// ────────────────────────── 1. range classification ────────────────────────
const CLASS_ROWS = [
  ['Simulation', 'Not the delivered class',
   'A modelled environment emitting synthetic telemetry, with no live systems under test. The platform includes a simulation adapter, but it operates as a declared degradation tier inside the emulation range. See the note below.'],
  ['Overlay', 'Excluded',
   'A range overlaid on the Purchaser live or production infrastructure. The platform never attaches to, instruments, or executes against production assets. Every target is a disposable asset the platform creates and destroys.'],
  ['Emulation', 'Delivered',
   'Adversary behaviour executed as genuine commands against real, purpose-built targets inside an isolated range with no egress, capturing actual stdout, stderr, exit code and timing. Targets include a persistent victim host, a reachable web application, and a real LDAP directory seeded with synthetic users.'],
  ['Hybrid', 'Not offered',
   'Two or more of the above classes delivered as co-equal scope. See the scope and pricing note below.'],
];

const CW = [1500, 2100, 6480];
const classification = [
  h1('1.  Cyber Range Classification'),
  p([t('The solution is offered as an '), t('emulation-class cyber range', { bold: true, color: NAVY }),
     t('. A single class is declared deliberately, so that the scope of supply, the target estate to be built, and the price are unambiguous and directly comparable across bidders.')],
    { after: 200 }),
  table(CW, [
    headerRow(CW, ['Range class', 'Position', 'Basis']),
    ...CLASS_ROWS.map(([a, b, c], i) => {
      const delivered = b === 'Delivered';
      return new TableRow({
        children: [
          cell(p([t(a, { bold: true, color: delivered ? NAVY : INK })], { after: 0 }), CW[0],
               { fill: delivered ? TINT : undefined }),
          cell(p([t(b, { bold: delivered, color: delivered ? GREEN : MUTED })], { after: 0 }), CW[1],
               { fill: delivered ? TINT : undefined }),
          cell(p([t(c, { size: 19, color: INK })], { after: 0, line: 268 }), CW[2],
               { fill: delivered ? TINT : undefined,
                 bottomRule: i === CLASS_ROWS.length - 1 ? hair(NAVY, 4) : hair() }),
        ],
      });
    }),
  ]),
  note('Simulation adapter.',
    'Where a target platform is unavailable — the Windows modules, or any host without the container execution tier — the platform falls back to a simulation adapter that emits the telemetry the module declares it would produce. Every timeline event is labelled real or simulated, so the fidelity of each record is explicit. This is a resilience property of the emulation range. It is not a second range class, it is not separately scoped, and it does not make this a hybrid submission.'),
  note('Scope and pricing.',
    'A second range class delivered as co-equal scope — most commonly emulation combined with an overlay onto live Purchaser infrastructure — is a materially different engagement. It changes the target estate, the safety and authorisation model, the isolation boundary, and the assurance obligations. Such a requirement is treated as a separate scope of supply, priced separately. It is not covered by the price submitted against this matrix.'),
];

// ──────────────────────────── 2. compliance matrix ─────────────────────────
const ARCH = {
  1: 'H1 · H2', 2: 'E2 · T1', 3: 'E2 · T1 · T2 · T3', 4: 'E2 · E5', 5: 'G3',
  6: 'G2 · G3', 7: 'G1 · E1', 8: 'E4', 9: 'H1 · E5', 10: 'E5', 11: 'E4 · E5',
  12: 'E5 · E6', 13: 'E4 · H1', 14: 'E4 · E5', 15: 'H1 · H2', 16: 'H2',
  17: 'G3 · H1 · H2', 18: 'G3 · H1 · E3', 19: 'G2', 20: 'G1 · E1 · E3', 21: 'H2',
  22: 'E6', 23: 'H2 · T1', 24: 'H2 · E5', 25: 'H2', 26: 'All layers',
};

const MW = [620, 6060, 1400, 2000];
const matrix = [
  h1('2.  Compliance Matrix'),
  p([t('Each requirement carries an architecture reference to the mandatory components defined in '),
     t('Appendix A', { bold: true, color: NAVY }),
     t('. A bidder claiming compliance against a requirement is required to evidence the components named against it.')],
    { after: 200 }),
  table(MW, [
    headerRow(MW, ['#', 'Requirement', 'Compliance', 'Architecture'],
              [AlignmentType.LEFT, AlignmentType.LEFT, AlignmentType.CENTER, AlignmentType.CENTER]),
    ...KEEP.map((r, i) => new TableRow({
      children: [
        cell(p([t(r.sl, { size: 19, bold: true, color: MUTED })], { after: 0 }), MW[0],
             { fill: i % 2 ? 'FAFCFD' : undefined }),
        cell([
          p([t(r.title, { bold: true, color: NAVY, size: 20 })], { after: 50, line: 264 }),
          p([t(r.body, { size: 18, color: INK })], { after: 0, line: 258 }),
        ], MW[1], { fill: i % 2 ? 'FAFCFD' : undefined }),
        cell(p([t(r.comp, { size: 19, bold: true, color: GREEN })],
               { after: 0, align: AlignmentType.CENTER }), MW[2],
             { fill: i % 2 ? 'FAFCFD' : undefined }),
        cell(p([t(ARCH[Number(r.sl)] || '', { size: 18, color: MUTED })],
               { after: 0, align: AlignmentType.CENTER }), MW[3],
             { fill: i % 2 ? 'FAFCFD' : undefined,
               bottomRule: i === KEEP.length - 1 ? hair(NAVY, 4) : hair() }),
      ],
    })),
  ]),
  p([t('Every capability stated above was verified directly against the platform content catalog, API surface and automated test suite at the time of writing. The matrix states delivered capability only.',
       { size: 18, italics: true, color: MUTED })],
    { before: 220 }),
];

// ──────────────────────────────── appendix A ───────────────────────────────
const COMP = [
  ['G1', 'Content & Governance', 'Safety Classification',
   'Every executable item carries S0, S1, S2 or Prohibited with a named approval authority.'],
  ['G2', 'Content & Governance', 'Framework Crosswalks',
   'Technique-level mapping to NIST CSF 2.0, NICE, CIS v8 and CAE-CD for curriculum and accreditation evidence.'],
  ['G3', 'Content & Governance', 'Signed Scenario & Module Catalog',
   'The authoritative record of what may run. Unsigned content is not executable.'],
  ['H1', 'Exercise Host', 'Red / Blue / Purple Role Workspaces',
   'Role-separated workspaces, including the redacted defender view (fog of war).'],
  ['H2', 'Exercise Host', 'Control Plane',
   'Enforced range lifecycle state machine, RBAC, authentication and the programmatic API.'],
  ['E1', 'Execution Guardrails', 'Signature & Safety Gate',
   'Refuses unsigned modules and blocks the Prohibited class for every role, administrators included.'],
  ['E2', 'Execution Guardrails', 'Isolation Enforcement',
   'No egress, no host mounts, CPU, memory and process-count caps, and bounded per-module timeouts.'],
  ['E3', 'Execution Guardrails', 'S2 Approval Gate',
   'Human-in-the-loop authorisation for high-impact lab actions, restricted to instructor and administrator.'],
  ['E4', 'Execution Guardrails', 'Detection Engine',
   'Versioned rules evaluated automatically against captured telemetry, recording the rule, matched evidence, severity and detection latency.'],
  ['E5', 'Execution Guardrails', 'Evidence Timeline',
   'One synchronized UTC timeline carrying integrity hashes, lockable at exercise completion.'],
  ['E6', 'Execution Guardrails', 'Append-Only Audit Ledger',
   'Immutable record of every state change, including score overrides and quarantine release.'],
  ['T1', 'Emulation Target Estate', 'Victim Host',
   'Persistent target on which a foothold established in one step survives into the next.'],
  ['T2', 'Emulation Target Estate', 'Web App Target',
   'Reachable over the range network, so behaviours traverse a connected environment.'],
  ['T3', 'Emulation Target Estate', 'LDAP Directory',
   'Real directory seeded with synthetic domain users, providing a genuine identity attack surface.'],
];

const AW = [640, 2000, 2600, 4840];
const IMG_PX_W = 620;
const appendix = [
  p([new PageBreak()], { after: 0 }),
  eyebrow('Appendix A'),
  p([t('Reference Architecture', { size: 34, bold: true, color: NAVY })], { after: 60 }),
  p([t('Mandatory conformance', { size: 21, color: MUTED })],
    { after: 140, border: { bottom: { style: BorderStyle.SINGLE, size: 10, color: ACCENT, space: 10 } } }),
  p([t('This appendix defines the mandatory functional decomposition of the solution. It forms part of the requirement. Every entry in the compliance matrix carries an architecture reference to the components below, and a bidder claiming compliance is required to evidence each referenced component.')],
    { before: 220 }),
  note('Conformance rule.',
    'The four layers of Figure A-1 are mandatory and must be supplied as one integrated platform by a single supplier. A response that omits a layer, that sources a layer from a third-party product the bidder does not control, or that satisfies a layer by manual process or documented policy in place of enforcement in the product, does not meet this requirement. In particular, the guardrail layer (E1 to E6) must be enforced in the execution path itself, so that a non-compliant action is prevented rather than merely recorded.'),
  h2('Figure A-1  ·  Emulation-class reference architecture'),
  new Paragraph({
    alignment: AlignmentType.CENTER,
    spacing: { before: 60, after: 120 },
    children: [new ImageRun({
      data: fs.readFileSync('../appendix_architecture.png'), type: 'png',
      transformation: { width: IMG_PX_W, height: Math.round(IMG_PX_W * 2320 / 2120) },
    })],
  }),
  p([new PageBreak()], { after: 0 }),
  h2('Table A-1  ·  Mandatory architecture components'),
  table(AW, [
    headerRow(AW, ['Ref', 'Layer', 'Component', 'Mandatory function']),
    ...COMP.map(([ref, layer, comp, fn], i) => new TableRow({
      children: [
        cell(p([t(ref, { bold: true, color: ACCENT, size: 19 })], { after: 0 }), AW[0],
             { fill: i % 2 ? 'FAFCFD' : undefined }),
        cell(p([t(layer, { size: 18, color: MUTED })], { after: 0, line: 258 }), AW[1],
             { fill: i % 2 ? 'FAFCFD' : undefined }),
        cell(p([t(comp, { size: 19, bold: true, color: NAVY })], { after: 0, line: 258 }), AW[2],
             { fill: i % 2 ? 'FAFCFD' : undefined }),
        cell(p([t(fn, { size: 18, color: INK })], { after: 0, line: 258 }), AW[3],
             { fill: i % 2 ? 'FAFCFD' : undefined,
               bottomRule: i === COMP.length - 1 ? hair(NAVY, 4) : hair() }),
      ],
    })),
  ]),
  note('Evaluation.',
    'Bidders are required to submit a completed copy of Table A-1 identifying, for each component, the module or subsystem of their solution that performs the stated function, together with the evidence by which it can be demonstrated in a technical evaluation. A component evidenced only by roadmap commitment is recorded as non-compliant for that row.'),
];

// ───────────────────────────────── document ────────────────────────────────
const doc = new Document({
  creator: 'VotalAI',
  title: 'CyberRange — Technical Capabilities Compliance Matrix',
  description: 'Emulation-class cyber range capability response with mandatory reference architecture',
  styles: { default: { document: { run: { font: F, size: 20, color: INK } } } },
  sections: [{
    properties: {
      page: {
        size: { width: 12240, height: 15840 },
        margin: { top: 1080, right: 1080, bottom: 1080, left: 1080, header: 600, footer: 500 },
      },
      titlePage: true,
    },
    headers: {
      default: new Header({ children: [p([
        t('CyberRange  ·  Technical Capabilities Compliance Matrix', { size: 15, color: MUTED })],
        { after: 0, border: { bottom: { style: BorderStyle.SINGLE, size: 3, color: RULE, space: 5 } } })] }),
      first: new Header({ children: [new Paragraph({ children: [] })] }),
    },
    footers: {
      default: new Footer({ children: [new Paragraph({
        alignment: AlignmentType.RIGHT,
        children: [
          new TextRun({ text: 'Votal  ·  CyberRange', font: F, size: 15, color: MUTED }),
          new TextRun({ text: '          ', font: F, size: 15 }),
          new TextRun({ children: [PageNumber.CURRENT], font: F, size: 15, color: MUTED }),
          new TextRun({ text: ' / ', font: F, size: 15, color: MUTED }),
          new TextRun({ children: [PageNumber.TOTAL_PAGES], font: F, size: 15, color: MUTED }),
        ],
      })] }),
      first: new Footer({ children: [new Paragraph({ children: [] })] }),
    },
    children: [...title, ...classification, ...matrix, ...appendix],
  }],
});

Packer.toBuffer(doc).then((b) => {
  fs.writeFileSync('clean.docx', b);
  console.log('wrote clean.docx', b.length, 'bytes;', KEEP.length, 'requirement rows');
});
