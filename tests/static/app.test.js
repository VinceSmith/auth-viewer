/**
 * JavaScript unit tests for app/static/app.js.
 *
 * Uses jsdom to provide a browser-like DOM environment.
 * Each test creates a fresh window instance so globals don't leak between tests.
 *
 * Focus areas:
 *   - matchFillToStep: pure color-matching logic
 *   - highlightDiagramStep / clearDiagramHighlight: SVG rect manipulation
 *   - setSteps / renderStepPills / showStep: step timeline rendering
 *   - diagram_index routing in showStep (the root cause of alignment bugs)
 *   - escapeHtml, getInitials, httpStatusText: pure helpers
 */

'use strict';

const { JSDOM } = require('jsdom');
const fs = require('fs');
const path = require('path');

const APP_JS = fs.readFileSync(
  path.resolve(__dirname, '../../app/static/app.js'),
  'utf8'
);

// ---------------------------------------------------------------------------
// Minimal HTML structure that satisfies all top-level getElementById calls
// ---------------------------------------------------------------------------

const MINIMAL_HTML = `<!DOCTYPE html><html><body>
  <div id="mermaid-container"></div>
  <div id="diagram-header"></div>
  <div id="flyout-panel"></div>
  <div id="flyout-backdrop"></div>
  <button id="btn-flyout"></button>
  <button id="btn-flyout-close"></button>
  <input name="auth_category" type="radio" value="user_auth" checked>
  <input name="client_type" type="radio" value="app" checked>
  <input id="reuse-id-token" type="checkbox">
  <label id="reuse-id-label"></label>
  <div id="step-timeline" style="display:none"></div>
  <div id="step-context-banner" style="display:none"></div>
  <div id="step-pills"></div>
  <p id="step-description"></p>
  <button id="btn-step-prev"></button>
  <button id="btn-step-next"></button>
  <div id="step-placeholder" style="display:block"></div>
  <div id="detail-tabs" style="display:none"></div>
  <div id="tab-bar"></div>
  <div id="summary-content"></div>
  <div id="section-request" style="display:none"></div>
  <div id="section-response" style="display:none"></div>
  <div id="section-req-token" style="display:none"></div>
  <div id="section-resp-token" style="display:none"></div>
  <div id="signin-log-toolbar"></div>
  <div id="signin-log-countdown"></div>
  <button class="tab-btn" data-tab="signin-log"></button>
  <div id="signin-log-content"></div>
  <div id="tab-signin-log-empty"></div>
  <button id="btn-signin-log-fetch"></button>
  <select id="scope-select"><option value="api://test/.default">Test</option></select>
  <button id="btn-execute"></button>
  <div id="signin-status"></div>
  <div id="auth-banner"></div>
  <div id="status-id"></div>
  <div id="status-refresh"></div>
  <div id="profile-avatar"></div>
  <span id="profile-initials"></span>
  <span id="tooltip-name"></span>
  <span id="tooltip-upn"></span>
  <span id="tooltip-oid"></span>
  <div id="id-pane"></div>
  <div id="id-pane-backdrop"></div>
  <pre id="id-pane-header"></pre>
  <pre id="id-pane-payload"></pre>
  <textarea id="id-pane-raw"></textarea>
  <button id="btn-signout"></button>
  <button id="btn-id-pane-close"></button>
  <div id="about-pane"></div>
  <div id="about-pane-backdrop"></div>
  <button id="btn-about"></button>
  <button id="btn-about-close"></button>
  <div id="tab-response-empty"></div>
  <pre id="resp-display"></pre>
  <div id="tab-request-empty"></div>
  <pre id="req-display"></pre>
  <pre id="req-token-display"></pre>
  <pre id="resp-token-display"></pre>
  <pre id="req-assertion-display"></pre>
  <div id="section-req-assertion" style="display:none"></div>
  <textarea id="req-at-raw"></textarea>
  <textarea id="req-assertion-raw"></textarea>
  <textarea id="req-user-assertion-raw"></textarea>
  <textarea id="resp-id-raw"></textarea>
  <textarea id="resp-at-raw"></textarea>
  <pre id="req-redirect-display"></pre>
  <div id="section-req-redirect" style="display:none"></div>
  <pre id="summary-display"></pre>
  <pre id="summary-response-display"></pre>
  <div id="tab-summary-empty"></div>
</body></html>`;

// Default STEP_FILLS: 4 distinct colors matching diagrams.py layout
const DEFAULT_STEP_FILLS = [
  [25, 35, 65],
  [25, 60, 35],
  [50, 50, 80],
  [60, 25, 45],
  [80, 40, 20],
  [20, 70, 60],
  [70, 20, 70],
];

/**
 * Create a fresh jsdom window with app.js loaded.
 * Returns the window object so tests can access globals directly.
 */
function createApp(stepFills = DEFAULT_STEP_FILLS) {
  const dom = new JSDOM(MINIMAL_HTML, {
    runScripts: 'dangerously',
    url: 'http://localhost:8000',
  });
  const win = dom.window;
  const doc = win.document;

  // Inject globals that the template normally provides
  win.STEP_FILLS = stepFills;

  // Stub fetch so async calls don't fail
  win.fetch = () => Promise.resolve({ ok: false, json: () => Promise.resolve({}) });

  // Stub mermaid so renderDiagram doesn't throw
  win.mermaid = {
    initialize: () => {},
    render: (id, code, cb) => { if (cb) cb('<svg></svg>'); return Promise.resolve({ svg: '<svg></svg>' }); },
  };

  // Patch getElementById to return a real stub div for any ID not in MINIMAL_HTML.
  // This prevents populateStepDetail (and other functions) from throwing on missing elements.
  const _origGetById = doc.getElementById.bind(doc);
  doc.getElementById = function(id) {
    const el = _origGetById(id);
    if (el) return el;
    // Create an off-DOM stub so .style.display, .innerHTML, .value, etc. all work
    const stub = doc.createElement('div');
    stub.id = id;
    return stub;
  };

  win.eval(APP_JS);
  return win;
}

// ---------------------------------------------------------------------------
// matchFillToStep
// ---------------------------------------------------------------------------

describe('matchFillToStep', () => {
  let w;
  beforeEach(() => { w = createApp([[25, 35, 65], [100, 150, 200]]); });

  test('returns -1 for non-rgb fill (hex color)', () => {
    expect(w.matchFillToStep('#ffffff')).toBe(-1);
  });

  test('returns -1 for empty fill', () => {
    expect(w.matchFillToStep('')).toBe(-1);
  });

  test('returns -1 for named color', () => {
    expect(w.matchFillToStep('white')).toBe(-1);
  });

  test('matches exact RGB color to index 0', () => {
    expect(w.matchFillToStep('rgb(25, 35, 65)')).toBe(0);
  });

  test('matches exact RGB color to index 1', () => {
    expect(w.matchFillToStep('rgb(100, 150, 200)')).toBe(1);
  });

  test('matches within +3 tolerance on all channels', () => {
    expect(w.matchFillToStep('rgb(28, 38, 68)')).toBe(0); // +3 exactly
  });

  test('matches within -3 tolerance', () => {
    expect(w.matchFillToStep('rgb(22, 32, 62)')).toBe(0); // -3 exactly
  });

  test('does NOT match when any channel exceeds ±3', () => {
    expect(w.matchFillToStep('rgb(29, 35, 65)')).toBe(-1); // r is +4
  });

  test('handles rgb with spaces (no commas)', () => {
    // Some browsers emit 'rgb(25 35 65)' syntax
    expect(w.matchFillToStep('rgb(25 35 65)')).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// highlightDiagramStep
// ---------------------------------------------------------------------------

describe('highlightDiagramStep', () => {
  let w;

  function makeMockRect(stepIndex) {
    const el = {
      _attrs: {},
      _style: {},
      style: {},
      getAttribute(k) { return this._attrs[k] ?? null; },
      setAttribute(k, v) { this._attrs[k] = v; },
    };
    el._attrs.stroke = 'none';
    el._attrs['stroke-width'] = '0';
    Object.defineProperty(el.style, 'opacity', {
      get() { return this._opacity || '1'; },
      set(v) { this._opacity = v; },
      configurable: true,
    });
    return { el, stepIndex };
  }

  beforeEach(() => {
    w = createApp();
    w.diagramStepRects = [];
  });

  test('does not throw when diagramStepRects is empty', () => {
    expect(() => w.highlightDiagramStep(0)).not.toThrow();
  });

  test('highlights the matching rect with blue stroke', () => {
    const rect = makeMockRect(2);
    w.diagramStepRects = [rect];
    w.highlightDiagramStep(2);
    expect(rect.el._attrs['stroke']).toBe('#4fc3f7');
    expect(rect.el._attrs['stroke-width']).toBe('3');
    expect(rect.el.style.opacity).toBe('1');
  });

  test('dims non-matching rects', () => {
    const matching = makeMockRect(2);
    const other = makeMockRect(0);
    w.diagramStepRects = [matching, other];
    w.highlightDiagramStep(2);
    expect(other.el.style.opacity).toBe('0.4');
  });

  test('dims non-matching rect with faded stroke color', () => {
    const matching = makeMockRect(1);
    const other = makeMockRect(3);
    w.diagramStepRects = [matching, other];
    w.highlightDiagramStep(1);
    expect(other.el._attrs['stroke']).toBe('#2a2a4a');
    expect(other.el._attrs['stroke-width']).toBe('1');
  });

  test('dims ALL rects when no rect matches the index', () => {
    const r0 = makeMockRect(0);
    const r1 = makeMockRect(1);
    w.diagramStepRects = [r0, r1];
    w.highlightDiagramStep(999); // no match
    expect(r0.el.style.opacity).toBe('0.4');
    expect(r1.el.style.opacity).toBe('0.4');
  });

  test('sets highlighted rect opacity to 1', () => {
    const rect = makeMockRect(0);
    rect.el.style.opacity = '0.4'; // was dimmed
    w.diagramStepRects = [rect];
    w.highlightDiagramStep(0);
    expect(rect.el.style.opacity).toBe('1');
  });
});

// ---------------------------------------------------------------------------
// clearDiagramHighlight
// ---------------------------------------------------------------------------

describe('clearDiagramHighlight', () => {
  let w;

  function makeMockRect() {
    const el = {
      _attrs: {},
      getAttribute(k) { return this._attrs[k] ?? null; },
      setAttribute(k, v) { this._attrs[k] = v; },
    };
    el._attrs.stroke = '#4fc3f7';
    el._attrs['stroke-width'] = '3';
    Object.defineProperty(el, 'style', {
      value: {
        get opacity() { return this._opacity || '1'; },
        set opacity(v) { this._opacity = v; },
      },
      configurable: true,
    });
    return { el };
  }

  beforeEach(() => {
    w = createApp();
    w.diagramStepRects = [];
  });

  test('does not throw when diagramStepRects is empty', () => {
    expect(() => w.clearDiagramHighlight()).not.toThrow();
  });

  test('sets stroke to "none" on all rects', () => {
    const r1 = makeMockRect();
    const r2 = makeMockRect();
    w.diagramStepRects = [r1, r2];
    w.clearDiagramHighlight();
    expect(r1.el._attrs['stroke']).toBe('none');
    expect(r2.el._attrs['stroke']).toBe('none');
  });

  test('sets stroke-width to "0" on all rects', () => {
    const rect = makeMockRect();
    w.diagramStepRects = [rect];
    w.clearDiagramHighlight();
    expect(rect.el._attrs['stroke-width']).toBe('0');
  });

  test('restores opacity to "1" on all rects', () => {
    const rect = makeMockRect();
    rect.el.style.opacity = '0.4';
    w.diagramStepRects = [rect];
    w.clearDiagramHighlight();
    expect(rect.el.style.opacity).toBe('1');
  });

  test('clears all rects, not just the first', () => {
    const rects = [makeMockRect(), makeMockRect(), makeMockRect()];
    rects.forEach(r => { r.el.style.opacity = '0.4'; });
    w.diagramStepRects = rects;
    w.clearDiagramHighlight();
    rects.forEach(r => {
      expect(r.el._attrs['stroke']).toBe('none');
      expect(r.el.style.opacity).toBe('1');
    });
  });
});

// ---------------------------------------------------------------------------
// setSteps
// ---------------------------------------------------------------------------

describe('setSteps', () => {
  let w;

  beforeEach(() => { w = createApp(); });

  test('hides timeline and shows placeholder for empty array', () => {
    w.setSteps([]);
    const timeline = w.document.getElementById('step-timeline');
    const placeholder = w.document.getElementById('step-placeholder');
    expect(timeline.style.display).toBe('none');
    expect(placeholder.style.display).toBe('block');
  });

  test('hides timeline and shows placeholder for null', () => {
    w.setSteps(null);
    const timeline = w.document.getElementById('step-timeline');
    expect(timeline.style.display).toBe('none');
  });

  test('shows timeline for non-empty steps', () => {
    w.setSteps([{ label: 'Step 1', description: 'First step', tokens: {}, highlights: {} }]);
    const timeline = w.document.getElementById('step-timeline');
    expect(timeline.style.display).toBe('block');
  });

  test('resets currentStepIndex to 0 on each call', () => {
    const steps = [
      { label: 'A', description: '', tokens: {}, highlights: {} },
      { label: 'B', description: '', tokens: {}, highlights: {} },
    ];
    w.setSteps(steps);
    w.currentStepIndex = 1; // simulate user navigating
    w.setSteps(steps);
    expect(w.currentStepIndex).toBe(0);
  });

  test('sets currentSteps to provided array', () => {
    const steps = [
      { label: 'Step A', description: '', tokens: {}, highlights: {} },
    ];
    w.setSteps(steps);
    expect(w.currentSteps).toEqual(steps);
  });

  test('empty array resets currentSteps', () => {
    w.setSteps([{ label: 'S', description: '', tokens: {}, highlights: {} }]);
    w.setSteps([]);
    expect(w.currentSteps).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// renderStepPills
// ---------------------------------------------------------------------------

describe('renderStepPills', () => {
  let w;

  beforeEach(() => { w = createApp(); });

  test('creates one pill per step', () => {
    w.currentSteps = [
      { label: 'Alpha', description: '', tokens: {}, highlights: {} },
      { label: 'Beta', description: '', tokens: {}, highlights: {} },
      { label: 'Gamma', description: '', tokens: {}, highlights: {} },
    ];
    w.currentStepIndex = 0;
    w.renderStepPills();
    const pills = w.document.querySelectorAll('#step-pills .step-pill');
    expect(pills.length).toBe(3);
  });

  test('pill numbers are 1-indexed', () => {
    w.currentSteps = [
      { label: 'First', description: '', tokens: {}, highlights: {} },
      { label: 'Second', description: '', tokens: {}, highlights: {} },
    ];
    w.currentStepIndex = 0;
    w.renderStepPills();
    const numbers = w.document.querySelectorAll('#step-pills .step-number');
    expect(numbers[0].textContent).toBe('1');
    expect(numbers[1].textContent).toBe('2');
  });

  test('active pill has "active" class', () => {
    w.currentSteps = [
      { label: 'A', description: '', tokens: {}, highlights: {} },
      { label: 'B', description: '', tokens: {}, highlights: {} },
    ];
    w.currentStepIndex = 1;
    w.renderStepPills();
    const pills = w.document.querySelectorAll('#step-pills .step-pill');
    expect(pills[0].classList.contains('active')).toBe(false);
    expect(pills[1].classList.contains('active')).toBe(true);
  });

  test('connectors are added between pills (n-1 connectors for n pills)', () => {
    w.currentSteps = [
      { label: 'A', description: '', tokens: {}, highlights: {} },
      { label: 'B', description: '', tokens: {}, highlights: {} },
      { label: 'C', description: '', tokens: {}, highlights: {} },
    ];
    w.currentStepIndex = 0;
    w.renderStepPills();
    const connectors = w.document.querySelectorAll('#step-pills .step-connector');
    expect(connectors.length).toBe(2); // 3 pills → 2 connectors
  });

  test('no connector after last pill', () => {
    w.currentSteps = [
      { label: 'Only', description: '', tokens: {}, highlights: {} },
    ];
    w.currentStepIndex = 0;
    w.renderStepPills();
    const connectors = w.document.querySelectorAll('#step-pills .step-connector');
    expect(connectors.length).toBe(0);
  });

  test('pill label text is the step label', () => {
    w.currentSteps = [
      { label: 'Token Exchange', description: '', tokens: {}, highlights: {} },
    ];
    w.currentStepIndex = 0;
    w.renderStepPills();
    const label = w.document.querySelector('#step-pills .step-label');
    expect(label.textContent).toBe('Token Exchange');
  });

  test('HTML-special characters in label are escaped', () => {
    w.currentSteps = [
      { label: '<script>alert(1)</script>', description: '', tokens: {}, highlights: {} },
    ];
    w.currentStepIndex = 0;
    w.renderStepPills();
    const label = w.document.querySelector('#step-pills .step-label');
    // The label's innerHTML should NOT contain a live script tag
    expect(label.innerHTML).not.toContain('<script>');
    expect(label.textContent).toContain('script'); // text content should have the text
  });
});

// ---------------------------------------------------------------------------
// showStep: diagram_index routing (THE CRITICAL BUG TESTS)
// ---------------------------------------------------------------------------

describe('showStep: diagram_index routing', () => {
  let w;

  // Builds a mock SVG rect whose style.opacity state can be inspected.
  // Uses Object.defineProperty on el.style (same pattern as highlightDiagramStep tests).
  function makeMockRect(stepIndex) {
    const el = {
      _attrs: {},
      getAttribute(k) { return this._attrs[k] ?? null; },
      setAttribute(k, v) { this._attrs[k] = v; },
      style: {},
    };
    el._attrs['stroke'] = 'none';
    el._attrs['stroke-width'] = '0';
    Object.defineProperty(el.style, 'opacity', {
      get() { return this._opacity !== undefined ? this._opacity : '1'; },
      set(v) { this._opacity = v; },
      configurable: true,
    });
    return { el, stepIndex };
  }

  function makeStep(label, diagram_index) {
    return {
      label, description: '', tokens: {}, highlights: {},
      diagram_index, request: null, response: null,
    };
  }

  // Helper predicates
  function isHighlighted(r) { return r.el._attrs['stroke'] === '#4fc3f7'; }
  function isCleared(r) { return r.el._attrs['stroke'] === 'none' && r.el.style.opacity === '1'; }
  function isDimmed(r) { return r.el.style.opacity === '0.4'; }

  beforeEach(() => {
    w = createApp();
    w.diagramStepRects = [];
  });

  test('step with diagram_index=-1 clears all rect highlights', () => {
    // Pre-highlight rect 0 so clearDiagramHighlight has something to clear
    const r0 = makeMockRect(0);
    r0.el._attrs['stroke'] = '#4fc3f7';
    r0.el.style.opacity = '0.4';
    w.diagramStepRects = [r0];
    // Use setSteps so the let-bound currentSteps is updated; it auto-calls showStep(0)
    w.setSteps([makeStep('Token Cache Hit', -1)]);
    expect(isCleared(r0)).toBe(true);
    expect(isHighlighted(r0)).toBe(false);
  });

  test('step with diagram_index=0 highlights rect with stepIndex=0', () => {
    const r0 = makeMockRect(0);
    const r1 = makeMockRect(1);
    w.diagramStepRects = [r0, r1];
    w.setSteps([makeStep('Authorize Redirect', 0)]);
    expect(isHighlighted(r0)).toBe(true);
    expect(isDimmed(r1)).toBe(true);
  });

  test('step with diagram_index=2 highlights rect 2, NOT rect 0 (the core regression)', () => {
    // THE CORE BUG TEST:
    // Pill at array index 0 has diagram_index=2.
    // WITHOUT the fix, showStep(0) calls highlightDiagramStep(0) → highlights rect 0.
    // WITH the fix,  showStep(0) calls highlightDiagramStep(2) → highlights rect 2.
    const r0 = makeMockRect(0);
    const r1 = makeMockRect(1);
    const r2 = makeMockRect(2);
    w.diagramStepRects = [r0, r1, r2];
    w.setSteps([makeStep('Call API A', 2)]); // array index 0, diagram_index 2
    expect(isHighlighted(r2)).toBe(true);   // rect 2 highlighted ✓
    expect(isDimmed(r0)).toBe(true);         // rect 0 NOT highlighted ✓
    expect(isDimmed(r1)).toBe(true);
  });

  test('step with diagram_index=5 highlights rect 5', () => {
    const rects = [0, 1, 2, 3, 4, 5, 6].map(makeMockRect);
    w.diagramStepRects = rects;
    w.setSteps([makeStep('Call API B (OBO)', 5)]);
    expect(isHighlighted(rects[5])).toBe(true);
    for (let i = 0; i < 7; i++) {
      if (i !== 5) expect(isDimmed(rects[i])).toBe(true);
    }
  });

  test('step without diagram_index falls back to array index', () => {
    // Backward compat: old step objects without diagram_index use position
    const r0 = makeMockRect(0);
    const r1 = makeMockRect(1);
    w.diagramStepRects = [r0, r1];
    // No diagram_index on this step; fallback to array position 0
    w.setSteps([{ label: 'No Index', description: '', tokens: {}, highlights: {}, request: null, response: null }]);
    expect(isHighlighted(r0)).toBe(true);
    expect(isDimmed(r1)).toBe(true);
  });

  test('cached token (diagram_index=-1) then resource (diagram_index=2): pills route to correct rects', () => {
    // Simulates the EXACT bug scenario:
    // - Pill 0: Token Cache Hit (diagram_index=-1) → should CLEAR, not highlight rect 0
    // - Pill 1: Call Resource  (diagram_index=2)  → should highlight rect 2, not rect 1
    const r0 = makeMockRect(0);
    const r1 = makeMockRect(1);
    const r2 = makeMockRect(2);
    w.diagramStepRects = [r0, r1, r2];
    // setSteps calls showStep(0) → diagram_index=-1 → clearDiagramHighlight
    w.setSteps([
      makeStep('Token Cache Hit', -1),
      makeStep('Call Resource', 2),
    ]);
    // After setSteps, showStep(0) was called: all rects must be cleared, not highlighted
    expect(isCleared(r0)).toBe(true);
    expect(isCleared(r1)).toBe(true);
    expect(isCleared(r2)).toBe(true);
    expect(isHighlighted(r0)).toBe(false);

    // Click second pill (Call Resource) → must highlight rect 2, not rect 1
    w.showStep(1);
    expect(isHighlighted(r2)).toBe(true);
    expect(isDimmed(r0)).toBe(true);
    expect(isDimmed(r1)).toBe(true);
  });

  test('showStep ignores out-of-bounds index (negative)', () => {
    w.setSteps([makeStep('A', 0)]);
    expect(() => w.showStep(-1)).not.toThrow();
  });

  test('showStep ignores out-of-bounds index (too high)', () => {
    w.setSteps([makeStep('A', 0)]);
    expect(() => w.showStep(99)).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// showStep: pill active/completed states
// ---------------------------------------------------------------------------

describe('showStep: pill states', () => {
  let w;

  function makeStep(label) {
    return { label, description: '', tokens: {}, highlights: {}, diagram_index: -1, request: null, response: null };
  }

  beforeEach(() => {
    w = createApp();
    // These stubs don't affect let-bound locals in app.js, but the getElementById
    // stub in createApp() prevents populateStepDetail from throwing on missing IDs.
  });

  test('active pill has "active" class, others do not', () => {
    w.setSteps([makeStep('A'), makeStep('B'), makeStep('C')]);
    w.showStep(1);
    const pills = w.document.querySelectorAll('#step-pills .step-pill');
    expect(pills[0].classList.contains('active')).toBe(false);
    expect(pills[1].classList.contains('active')).toBe(true);
    expect(pills[2].classList.contains('active')).toBe(false);
  });

  test('pills before active step have "completed" class', () => {
    w.setSteps([makeStep('A'), makeStep('B'), makeStep('C')]);
    w.showStep(2);
    const pills = w.document.querySelectorAll('#step-pills .step-pill');
    expect(pills[0].classList.contains('completed')).toBe(true);
    expect(pills[1].classList.contains('completed')).toBe(true);
    expect(pills[2].classList.contains('completed')).toBe(false);
  });

  test('prev button disabled at step 0', () => {
    w.setSteps([makeStep('A'), makeStep('B')]);
    w.showStep(0);
    expect(w.document.getElementById('btn-step-prev').disabled).toBe(true);
  });

  test('next button disabled at last step', () => {
    w.setSteps([makeStep('A'), makeStep('B')]);
    w.showStep(1);
    expect(w.document.getElementById('btn-step-next').disabled).toBe(true);
  });

  test('both prev and next enabled in the middle', () => {
    w.setSteps([makeStep('A'), makeStep('B'), makeStep('C')]);
    w.showStep(1);
    expect(w.document.getElementById('btn-step-prev').disabled).toBe(false);
    expect(w.document.getElementById('btn-step-next').disabled).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Pure helper: escapeHtml
// ---------------------------------------------------------------------------

describe('escapeHtml', () => {
  let w;
  beforeEach(() => { w = createApp(); });

  test('escapes < and >', () => {
    expect(w.escapeHtml('<b>bold</b>')).toBe('&lt;b&gt;bold&lt;/b&gt;');
  });

  test('escapes &', () => {
    expect(w.escapeHtml('a & b')).toBe('a &amp; b');
  });

  test('does not double-escape already-escaped entities', () => {
    // The browser textContent approach escapes once
    const result = w.escapeHtml('<script>');
    expect(result).toContain('&lt;');
    expect(result).not.toContain('<script>');
  });

  test('returns empty string unchanged', () => {
    expect(w.escapeHtml('')).toBe('');
  });

  test('passes through safe text unchanged', () => {
    expect(w.escapeHtml('Hello World 123')).toBe('Hello World 123');
  });

  test('escapes angle brackets in XSS attempt', () => {
    const result = w.escapeHtml('<img src=x onerror=alert(1)>');
    expect(result).not.toContain('<img');
    expect(result).toContain('&lt;img');
  });
});

// ---------------------------------------------------------------------------
// Pure helper: getInitials
// ---------------------------------------------------------------------------

describe('getInitials', () => {
  let w;
  beforeEach(() => { w = createApp(); });

  test('returns first and last initials for two-word name', () => {
    expect(w.getInitials('Alice Smith')).toBe('AS');
  });

  test('returns single initial for one-word name', () => {
    expect(w.getInitials('Alice')).toBe('A');
  });

  test('uses first and last word for three-word name', () => {
    expect(w.getInitials('Alice Marie Smith')).toBe('AS');
  });

  test('returns "?" for null', () => {
    expect(w.getInitials(null)).toBe('?');
  });

  test('returns "?" for empty string', () => {
    expect(w.getInitials('')).toBe('?');
  });

  test('returns uppercase initials', () => {
    expect(w.getInitials('alice smith')).toBe('AS');
  });
});

// ---------------------------------------------------------------------------
// Execute flow: diagram variant selection from API response
// ---------------------------------------------------------------------------

describe('execute flow: uses diagram from API response, not getDiagramKey()', () => {
  // The critical regression: when /api/execute returns a diagram field
  // (e.g. the _cached or _silent variant), the JS must render THAT diagram
  // instead of re-fetching via getDiagramKey() which always returns the base
  // flow type (e.g. "agent_id_obo" instead of "agent_id_obo_cached").

  function createAppWithFetch(fetchImpl) {
    const dom = new JSDOM(MINIMAL_HTML, { runScripts: 'dangerously', url: 'http://localhost:8000' });
    const win = dom.window;
    const doc = win.document;
    win.STEP_FILLS = DEFAULT_STEP_FILLS;
    win.fetch = fetchImpl;
    win.mermaid = {
      initialize: () => {},
      render: (id, code) => Promise.resolve({ svg: `<svg data-code="${code.slice(0, 20)}"></svg>` }),
    };
    const _origGetById = doc.getElementById.bind(doc);
    doc.getElementById = (id) => _origGetById(id) || doc.createElement('div');
    // Suppress setInterval to prevent test from hanging (startSigninLogPolling)
    win.setInterval = () => 0;
    win.clearInterval = () => {};
    dom.window.eval(APP_JS);
    return win;
  }

  test('renderMermaid is called with diagram from data.diagram, not a separate /api/diagram/ fetch', async () => {
    const cachedDiagram = 'sequenceDiagram\n  Note over C: Token from cache';
    const diagramFetchUrls = [];

    const w = createAppWithFetch((url, opts) => {
      if (url.startsWith('/api/diagram/')) {
        diagramFetchUrls.push(url);
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ diagram: 'WRONG_DIAGRAM_FROM_SEPARATE_FETCH' }),
        });
      }
      if (url === '/api/execute') {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({
            result: {
              steps: [
                { label: 'Token Cache Hit', diagram_index: -1, description: 'cached', tokens: {}, highlights: {} },
                { label: 'Parent Token', diagram_index: 0, description: 'parent', tokens: {}, highlights: {} },
              ],
              context: '',
            },
            diagram: cachedDiagram,
          }),
        });
      }
      // Handle all other endpoints (highlights, signin-log, etc.)
      return Promise.resolve({ ok: true, json: () => Promise.resolve({}) });
    });

    // Spy on renderMermaid by intercepting mermaid.render calls
    const renderedCodes = [];
    w.mermaid.render = (id, code) => {
      renderedCodes.push(code);
      return Promise.resolve({ svg: '<svg></svg>' });
    };

    // Drain DOMContentLoaded async operations before starting the test
    await new Promise(r => setTimeout(r, 50));

    // Clear any diagram fetches from DOMContentLoaded initialization
    diagramFetchUrls.length = 0;
    renderedCodes.length = 0;

    // Use client_credentials so btn-execute goes to /api/execute, not /auth/login redirect
    w.authCategory = 'client_credentials';

    // Trigger execute by clicking btn-execute
    const btnExecute = w.document.getElementById('btn-execute');
    btnExecute.click();
    // Wait for async ops to complete
    await new Promise(r => setTimeout(r, 100));

    // The /api/diagram/* endpoint must NOT be called after execute succeeds
    expect(diagramFetchUrls).toHaveLength(0);

    // The diagram rendered must be the one from data.diagram
    expect(renderedCodes.some(c => c === cachedDiagram)).toBe(true);
    expect(renderedCodes.some(c => c === 'WRONG_DIAGRAM_FROM_SEPARATE_FETCH')).toBe(false);
  });
});


// ---------------------------------------------------------------------------
// Silent acquire: error from /api/execute must be shown, not swallowed
// ---------------------------------------------------------------------------

describe('silent acquire: execute error handling', () => {
  function createAppWithFetch(fetchImpl) {
    const dom = new JSDOM(MINIMAL_HTML, { runScripts: 'dangerously', url: 'http://localhost:8000' });
    const win = dom.window;
    const doc = win.document;
    win.STEP_FILLS = DEFAULT_STEP_FILLS;
    win.fetch = fetchImpl;
    win.mermaid = {
      initialize: () => {},
      render: (id, code) => Promise.resolve({ svg: '<svg></svg>' }),
    };
    const _origGetById = doc.getElementById.bind(doc);
    doc.getElementById = (id) => _origGetById(id) || doc.createElement('div');
    win.setInterval = () => 0;
    win.clearInterval = () => {};
    dom.window.eval(APP_JS);
    return win;
  }

  test('shows error when silent acquire succeeds but execute returns an error', async () => {
    const w = createAppWithFetch((url) => {
      if (url === '/api/silent-acquire') {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ access_token: 'fake-token' }),
        });
      }
      if (url === '/api/execute') {
        return Promise.resolve({
          ok: false,
          json: () => Promise.resolve({ error: 'token_expired', message: 'Your token has expired' }),
        });
      }
      return Promise.resolve({ ok: true, json: () => Promise.resolve({}) });
    });

    // Wait for DOMContentLoaded async ops
    await new Promise(r => setTimeout(r, 50));

    // Check "reuse session" checkbox to trigger silent acquire path
    w.document.getElementById('reuse-id-token').checked = true;
    // authCategory defaults to 'user_auth' in MINIMAL_HTML

    w.document.getElementById('btn-execute').click();
    await new Promise(r => setTimeout(r, 100));

    // Error must be displayed in the response panel, not silently swallowed
    const respDisplay = w.document.getElementById('resp-display');
    expect(respDisplay.textContent).toMatch(/token_expired|Your token has expired/);
  });
});


describe('httpStatusText', () => {
  let w;
  beforeEach(() => { w = createApp(); });

  test('200 → OK', () => { expect(w.httpStatusText(200)).toBe('OK'); });
  test('400 → Bad Request', () => { expect(w.httpStatusText(400)).toBe('Bad Request'); });
  test('401 → Unauthorized', () => { expect(w.httpStatusText(401)).toBe('Unauthorized'); });
  test('500 → Internal Server Error', () => { expect(w.httpStatusText(500)).toBe('Internal Server Error'); });
  test('999 → empty string', () => { expect(w.httpStatusText(999)).toBe(''); });
  test('302 → Found', () => { expect(w.httpStatusText(302)).toBe('Found'); });
});
