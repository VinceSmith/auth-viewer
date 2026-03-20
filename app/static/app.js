/* ── Entra OAuth Explorer — Frontend Logic ── */

// ── State ──
let currentFlowType = 'auth_code';
let diagramCounter = 0;
let currentSteps = [];
let currentStepIndex = 0;
let highlightMap = {};
let diagramStepRects = [];

// Step rect fill colors — must match diagrams.py STEP_FILLS
const STEP_FILLS = [
    [25, 35, 65],
    [25, 60, 35],
    [65, 30, 25],
    [30, 55, 55],
    [55, 30, 55],
    [55, 55, 25],
];

// JWT claim descriptions for hover tooltips
const CLAIM_DESCRIPTIONS = {
    // Header claims
    typ: 'Token type (e.g. JWT)',
    alg: 'Signing algorithm (e.g. RS256)',
    kid: 'Key ID — identifies the signing key',
    x5t: 'X.509 certificate thumbprint (SHA-1)',
    nonce: 'Server nonce to prevent replay attacks',
    // Registered/standard claims
    iss: 'Issuer — the authority that issued this token',
    sub: 'Subject — unique identifier for the principal',
    aud: 'Audience — intended recipient (app/API)',
    exp: 'Expiration time (Unix timestamp)',
    _exp_utc: 'Expiration time (human-readable UTC)',
    nbf: 'Not before — token is not valid before this time',
    _nbf_utc: 'Not-before time (human-readable UTC)',
    iat: 'Issued at — when the token was created',
    _iat_utc: 'Issued-at time (human-readable UTC)',
    jti: 'JWT ID — unique identifier for this token',
    // Entra ID / Microsoft identity claims
    tid: 'Tenant ID — the Entra ID tenant',
    oid: 'Object ID — immutable user/principal identifier in the tenant',
    azp: 'Authorized party — client_id of the app that requested the token',
    azpacr: 'Authorized party auth method (0=public, 1=secret, 2=cert)',
    appid: 'Application ID — client_id (v1 tokens)',
    appidacr: 'Application auth method (v1 tokens)',
    idtyp: 'Token identity type (e.g. "app" for app-only tokens)',
    scp: 'Scope — delegated permissions granted to the app',
    roles: 'App roles assigned to the client',
    wids: 'Directory-wide roles assigned (e.g. Global Admin)',
    groups: 'Group IDs the user belongs to',
    // User profile claims
    name: 'Display name of the user',
    preferred_username: 'User\'s primary username (usually email/UPN)',
    upn: 'User Principal Name',
    unique_name: 'Unique display name (v1 tokens)',
    email: 'User\'s email address',
    given_name: 'User\'s first name',
    family_name: 'User\'s last name',
    ipaddr: 'IP address the token was issued from',
    // Auth context
    acr: 'Authentication context class reference (MFA level)',
    amr: 'Authentication methods (e.g. pwd, mfa, rsa)',
    auth_time: 'Time when the user last authenticated',
    login_hint: 'Opaque hint for seamless re-authentication',
    sid: 'Session ID for single sign-out',
    tenant_region_scope: 'Region of the tenant (e.g. NA, EU)',
    // Token exchange
    act: 'Actor — the entity acting on behalf of the subject',
    client_id: 'Client ID that requested this token',
    // OIDC
    ver: 'Token version (1.0 or 2.0)',
    aio: 'Azure internal opaque token (not for app use)',
    rh: 'Azure internal routing hint (not for app use)',
    xms_st: 'Token sub-type extension',
    xms_tcdt: 'Tenant creation date extension',
    xms_tdbr: 'Tenant data boundary region',
    // Agent ID specific
    fmi_path: 'Federated managed identity path (Agent Identity)',
    xms_mirid: 'Managed identity resource ID',
    xms_az: 'Azure-specific authorization context',
};

// ── DOM refs ──
const flowRadios = document.querySelectorAll('input[name="flow_type"]');
const scopeSelect = document.getElementById('scope-select');
const btnExecute = document.getElementById('btn-execute');
const mermaidContainer = document.getElementById('mermaid-container');

// Flyout
const flyoutPanel = document.getElementById('flyout-panel');
const flyoutBackdrop = document.getElementById('flyout-backdrop');
const btnFlyout = document.getElementById('btn-flyout');
const btnFlyoutClose = document.getElementById('btn-flyout-close');

// Step timeline
const stepTimeline = document.getElementById('step-timeline');
const stepPills = document.getElementById('step-pills');
const stepDescription = document.getElementById('step-description');
const btnStepPrev = document.getElementById('btn-step-prev');
const btnStepNext = document.getElementById('btn-step-next');
const highlightLegend = document.getElementById('highlight-legend');
const legendItems = document.getElementById('legend-items');

// Detail sections
const stepPlaceholder = document.getElementById('step-placeholder');
const sectionRequest = document.getElementById('section-request');
const sectionResponse = document.getElementById('section-response');
const sectionAccessToken = document.getElementById('section-access-token');
const sectionIdToken = document.getElementById('section-id-token');

// Flow-specific panels
const oboOptions = document.getElementById('obo-options');
const agentOboOptions = document.getElementById('agent-obo-options');
const deviceCodeOptions = document.getElementById('device-code-options');
const deviceCodeInfo = document.getElementById('device-code-info');
const deviceCodeInstructions = document.getElementById('device-code-instructions');
const sectionRefreshToken = document.getElementById('section-refresh-token');


// ══════════════════════════════════════════════════════════════════════════
// ── FLYOUT ──
// ══════════════════════════════════════════════════════════════════════════

function openFlyout() {
    flyoutPanel.classList.add('open');
    flyoutBackdrop.classList.add('open');
}

function closeFlyout() {
    flyoutPanel.classList.remove('open');
    flyoutBackdrop.classList.remove('open');
}

btnFlyout.addEventListener('click', openFlyout);
btnFlyoutClose.addEventListener('click', closeFlyout);
flyoutBackdrop.addEventListener('click', closeFlyout);

document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && flyoutPanel.classList.contains('open')) {
        closeFlyout();
    }
});


// ══════════════════════════════════════════════════════════════════════════
// ── HIGHLIGHT MAP ──
// ══════════════════════════════════════════════════════════════════════════

async function loadHighlights() {
    try {
        const resp = await fetch('/api/highlights');
        highlightMap = await resp.json();
        buildLegend();
    } catch { /* ignore */ }
}

function buildLegend() {
    legendItems.innerHTML = '';
    for (const [guid, info] of Object.entries(highlightMap)) {
        const item = document.createElement('span');
        item.className = 'legend-item';
        item.style.borderColor = info.color;
        item.style.color = info.color;
        item.textContent = info.label;
        item.title = guid;
        legendItems.appendChild(item);
    }
}


// ══════════════════════════════════════════════════════════════════════════
// ── FLOW TYPE & SCOPE ──
// ══════════════════════════════════════════════════════════════════════════

flowRadios.forEach(radio => {
    radio.addEventListener('change', (e) => {
        currentFlowType = e.target.value;
        updateFlowUI();
        loadDiagram(getDiagramKey());
    });
});

function updateFlowUI() {
    oboOptions.style.display = 'none';
    agentOboOptions.style.display = 'none';
    deviceCodeOptions.style.display = 'none';
    deviceCodeInfo.style.display = 'none';

    if (currentFlowType === 'obo') {
        oboOptions.style.display = 'block';
    } else if (currentFlowType === 'agent_id_obo') {
        agentOboOptions.style.display = 'block';
    } else if (currentFlowType === 'device_code') {
        deviceCodeOptions.style.display = 'block';
    }

    // Filter scope options by flow type
    let firstVisible = null;
    let currentStillVisible = false;
    for (const opt of scopeSelect.options) {
        const flows = (opt.dataset.flows || '').split(' ');
        const show = flows.includes(currentFlowType);
        opt.hidden = !show;
        if (show && !firstVisible) firstVisible = opt;
        if (show && opt.selected) currentStillVisible = true;
    }
    if (!currentStillVisible && firstVisible) firstVisible.selected = true;

    if (currentFlowType === 'auth_code' || currentFlowType === 'auth_code_pkce') {
        btnExecute.textContent = 'Sign In (Redirect)';
    } else if (currentFlowType === 'obo') {
        const mode = document.querySelector('input[name="obo_mode"]:checked')?.value || 'new';
        btnExecute.textContent = mode === 'reuse' ? 'Execute Flow' : 'Sign In (Redirect)';
    } else if (currentFlowType === 'agent_id_obo') {
        const mode = document.querySelector('input[name="agent_obo_mode"]:checked')?.value || 'new';
        btnExecute.textContent = mode === 'reuse' ? 'Execute Flow' : 'Sign In (Redirect)';
    } else if (currentFlowType === 'device_code') {
        btnExecute.textContent = 'Start Device Code Flow';
    } else {
        btnExecute.textContent = 'Execute Flow';
    }
}

function getScope() {
    return scopeSelect.value;
}

// Helper: get the effective diagram key for the current flow + mode
function getDiagramKey() {
    if (currentFlowType === 'obo') {
        const mode = document.querySelector('input[name="obo_mode"]:checked')?.value || 'new';
        return mode === 'reuse' ? 'obo_reuse' : 'obo';
    }
    if (currentFlowType === 'agent_id_obo') {
        const mode = document.querySelector('input[name="agent_obo_mode"]:checked')?.value || 'new';
        return mode === 'reuse' ? 'agent_id_obo_reuse' : 'agent_id_obo';
    }
    return currentFlowType;
}

// OBO/Agent OBO mode toggle handlers
document.querySelectorAll('input[name="obo_mode"]').forEach(radio => {
    radio.addEventListener('change', () => {
        const reuse = radio.value === 'reuse';
        document.getElementById('obo-reuse-hint').style.display = reuse ? 'block' : 'none';
        updateFlowUI();
        loadDiagram(getDiagramKey());
    });
});

document.querySelectorAll('input[name="agent_obo_mode"]').forEach(radio => {
    radio.addEventListener('change', () => {
        const reuse = radio.value === 'reuse';
        document.getElementById('agent-obo-reuse-hint').style.display = reuse ? 'block' : 'none';
        updateFlowUI();
        loadDiagram(getDiagramKey());
    });
});


// ══════════════════════════════════════════════════════════════════════════
// ── MERMAID DIAGRAM ──
// ══════════════════════════════════════════════════════════════════════════

async function loadDiagram(flowType) {
    try {
        const resp = await fetch(`/api/diagram/${flowType}`);
        const data = await resp.json();
        await renderMermaid(data.diagram);
    } catch (err) {
        mermaidContainer.innerHTML = `<p class="error-banner">Failed to load diagram: ${err.message}</p>`;
    }
}

async function renderMermaid(code) {
    diagramCounter++;
    const id = `mermaid-${diagramCounter}`;
    try {
        const { svg } = await mermaid.render(id, code);
        mermaidContainer.innerHTML = svg;
        bindDiagramClicks();
        if (currentSteps.length > 0) highlightDiagramStep(currentStepIndex);
    } catch (err) {
        mermaidContainer.innerHTML = `<pre class="code-block">${escapeHtml(code)}</pre>`;
        diagramStepRects = [];
    }
}


// ══════════════════════════════════════════════════════════════════════════
// ── CLICKABLE DIAGRAM ──
// ══════════════════════════════════════════════════════════════════════════

function bindDiagramClicks() {
    diagramStepRects = [];
    const svg = document.querySelector('#mermaid-container svg');
    if (!svg) return;

    const allRects = svg.querySelectorAll('rect');
    for (const rect of allRects) {
        const fill = rect.getAttribute('fill') || rect.style.fill || '';
        const idx = matchFillToStep(fill);
        if (idx >= 0) {
            diagramStepRects.push({ el: rect, stepIndex: idx });
            rect.style.cursor = 'pointer';
            rect.style.transition = 'stroke 0.2s, stroke-width 0.2s, opacity 0.2s';
            rect.addEventListener('click', () => {
                if (idx < currentSteps.length) showStep(idx);
            });
        }
    }
}

function matchFillToStep(fill) {
    const m = fill.match(/rgb\(\s*(\d+)[,\s]+(\d+)[,\s]+(\d+)\s*\)/);
    if (!m) return -1;
    const r = parseInt(m[1]), g = parseInt(m[2]), b = parseInt(m[3]);
    for (let i = 0; i < STEP_FILLS.length; i++) {
        const [sr, sg, sb] = STEP_FILLS[i];
        if (Math.abs(r - sr) <= 3 && Math.abs(g - sg) <= 3 && Math.abs(b - sb) <= 3) {
            return i;
        }
    }
    return -1;
}

function highlightDiagramStep(index) {
    for (const { el, stepIndex } of diagramStepRects) {
        if (stepIndex === index) {
            el.setAttribute('stroke', '#4fc3f7');
            el.setAttribute('stroke-width', '3');
            el.style.opacity = '1';
        } else {
            el.setAttribute('stroke', '#2a2a4a');
            el.setAttribute('stroke-width', '1');
            el.style.opacity = '0.4';
        }
    }
}

function clearDiagramHighlight() {
    for (const { el } of diagramStepRects) {
        el.setAttribute('stroke', 'none');
        el.setAttribute('stroke-width', '0');
        el.style.opacity = '1';
    }
}


// ══════════════════════════════════════════════════════════════════════════
// ── STEP-THROUGH ENGINE ──
// ══════════════════════════════════════════════════════════════════════════

function setSteps(steps) {
    currentSteps = steps || [];
    currentStepIndex = 0;

    if (currentSteps.length === 0) {
        stepTimeline.style.display = 'none';
        highlightLegend.style.display = 'none';
        clearDiagramHighlight();
        return;
    }

    stepTimeline.style.display = 'block';
    highlightLegend.style.display = 'flex';
    renderStepPills();
    showStep(0);
}

function renderStepPills() {
    stepPills.innerHTML = '';
    currentSteps.forEach((step, i) => {
        const pill = document.createElement('button');
        pill.className = 'step-pill' + (i === currentStepIndex ? ' active' : '');
        pill.innerHTML = `<span class="step-number">${i + 1}</span><span class="step-label">${escapeHtml(step.label)}</span>`;
        pill.title = step.description || step.label;
        pill.addEventListener('click', () => showStep(i));
        stepPills.appendChild(pill);

        if (i < currentSteps.length - 1) {
            const connector = document.createElement('span');
            connector.className = 'step-connector';
            connector.textContent = '→';
            stepPills.appendChild(connector);
        }
    });
}

function showStep(index) {
    if (index < 0 || index >= currentSteps.length) return;
    currentStepIndex = index;

    // Update pill states
    stepPills.querySelectorAll('.step-pill').forEach((pill, i) => {
        pill.classList.toggle('active', i === index);
        pill.classList.toggle('completed', i < index);
    });

    btnStepPrev.disabled = index === 0;
    btnStepNext.disabled = index === currentSteps.length - 1;

    const step = currentSteps[index];
    stepDescription.textContent = step.description || '';

    // Populate unified detail view
    populateStepDetail(step);

    // Highlight corresponding diagram rect
    highlightDiagramStep(index);
}

function populateStepDetail(step) {
    stepPlaceholder.style.display = 'none';

    // Request
    const req = step.request;
    if (req) {
        sectionRequest.style.display = 'block';
        const reqText = `${req.method} ${req.url}\n\nHeaders:\n${formatJson(req.headers)}\n\nBody:\n${formatJson(req.body)}`;
        setHighlightedHtml('req-display', reqText);
    } else {
        sectionRequest.style.display = 'none';
    }

    // Response
    const resp = step.response;
    if (resp) {
        sectionResponse.style.display = 'block';
        const respText = `Status: ${resp.status}\n\nHeaders:\n${formatJson(resp.headers)}\n\nBody:\n${formatJson(resp.body)}`;
        setHighlightedHtml('resp-display', respText);
    } else {
        sectionResponse.style.display = 'none';
    }

    // Access Token
    const tokens = step.tokens || {};
    if (tokens.access_token) {
        sectionAccessToken.style.display = 'block';
        setHighlightedHtml('at-header', formatJson(tokens.access_token.header));
        setHighlightedHtml('at-payload', formatJson(tokens.access_token.payload));
        document.getElementById('at-raw').value = tokens.access_token.raw || '';
    } else {
        sectionAccessToken.style.display = 'none';
    }

    // ID Token
    if (tokens.id_token) {
        sectionIdToken.style.display = 'block';
        setHighlightedHtml('id-header', formatJson(tokens.id_token.header));
        setHighlightedHtml('id-payload', formatJson(tokens.id_token.payload));
        document.getElementById('id-raw').value = tokens.id_token.raw || '';
    } else {
        sectionIdToken.style.display = 'none';
    }

    // Refresh Token presence
    if (tokens.refresh_token) {
        sectionRefreshToken.style.display = 'block';
        document.getElementById('refresh-token-note').textContent =
            '✓ Refresh token present — opaque to clients (not meant for introspection).';
    } else {
        sectionRefreshToken.style.display = 'none';
    }

    // If nothing is shown (display-only step with just description), show a note
    if (!req && !resp && !tokens.access_token && !tokens.id_token) {
        sectionRequest.style.display = 'block';
        setText('req-display', 'Display-only step — see the description above.');
    }
}

// Step navigation
btnStepPrev.addEventListener('click', () => showStep(currentStepIndex - 1));
btnStepNext.addEventListener('click', () => showStep(currentStepIndex + 1));

document.addEventListener('keydown', (e) => {
    if (currentSteps.length === 0) return;
    if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA' || e.target.tagName === 'SELECT') return;
    if (flyoutPanel.classList.contains('open')) return;
    if (e.key === 'ArrowLeft') {
        e.preventDefault();
        showStep(currentStepIndex - 1);
    } else if (e.key === 'ArrowRight') {
        e.preventDefault();
        showStep(currentStepIndex + 1);
    }
});


// ══════════════════════════════════════════════════════════════════════════
// ── COLOR-CODED HIGHLIGHTING ──
// ══════════════════════════════════════════════════════════════════════════

function highlightText(text) {
    let html = escapeHtml(text);
    // Add tooltips on JSON keys that match known JWT claims
    html = html.replace(/&quot;(\w+)&quot;(\s*:)/g, (match, key, colon) => {
        const desc = CLAIM_DESCRIPTIONS[key];
        if (desc) {
            return `<span class="claim-key" title="${escapeHtml(desc)}">&quot;${key}&quot;</span>${colon}`;
        }
        return match;
    });
    // Color-code tracked IDs
    for (const [value, info] of Object.entries(highlightMap)) {
        if (!value) continue;
        const escaped = value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        const re = new RegExp(escaped, 'g');
        html = html.replace(re,
            `<span class="hl" style="color:${info.color};background:${info.color}20;border-bottom:2px solid ${info.color}" title="${escapeHtml(info.label)}">${escapeHtml(value)}</span>`
        );
    }
    return html;
}

function setHighlightedHtml(id, text) {
    document.getElementById(id).innerHTML = highlightText(text);
}


// ══════════════════════════════════════════════════════════════════════════
// ── EXECUTE FLOW ──
// ══════════════════════════════════════════════════════════════════════════

btnExecute.addEventListener('click', async () => {
    const flowType = currentFlowType;
    const scope = getScope();

    // Close flyout on execute
    closeFlyout();

    if (flowType === 'auth_code') {
        window.location.href = `/auth/login?scope=${encodeURIComponent(scope)}&prompt=login`;
        return;
    }
    if (flowType === 'auth_code_pkce') {
        window.location.href = `/auth/login?scope=${encodeURIComponent(scope)}&use_pkce=true&prompt=login`;
        return;
    }
    if (flowType === 'obo') {
        const mode = document.querySelector('input[name="obo_mode"]:checked')?.value || 'new';
        if (mode === 'new') {
            window.location.href = `/auth/login?flow_type=obo&target_scope=${encodeURIComponent(scope)}&prompt=login`;
            return;
        }
        // Reuse mode — fall through to API execute below
    }
    if (flowType === 'agent_id_obo') {
        const mode = document.querySelector('input[name="agent_obo_mode"]:checked')?.value || 'new';
        if (mode === 'new') {
            window.location.href = `/auth/login?flow_type=agent_id_obo&target_scope=${encodeURIComponent(scope)}&prompt=login`;
            return;
        }
        // Reuse mode — fall through to API execute below
    }
    if (flowType === 'device_code') {
        openFlyout(); // keep flyout open for device code instructions
        await executeDeviceCodeStart(scope);
        return;
    }

    btnExecute.disabled = true;
    btnExecute.textContent = 'Executing...';

    try {
        const payload = { flow_type: flowType, scope: scope };
        const resp = await fetch('/api/execute', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });
        const data = await resp.json();

        if (data.error) {
            showError(data.error);
            return;
        }

        const result = data.result;
        if (result && result.steps && result.steps.length > 0) {
            setSteps(result.steps);
        } else {
            displayResultLegacy(result, flowType);
        }

        // Load the diagram matching the current mode (reuse vs new)
        await loadDiagram(getDiagramKey());
        if (currentSteps.length > 0) highlightDiagramStep(currentStepIndex);
        updateSessionStatus();
        await loadHighlights();
        // Re-render current step with updated highlights
        if (currentSteps.length > 0) showStep(currentStepIndex);
    } catch (err) {
        showError(err.message);
    } finally {
        btnExecute.disabled = false;
        updateFlowUI();
    }
});


// ── Device Code flow ──
async function executeDeviceCodeStart(scope) {
    btnExecute.disabled = true;
    btnExecute.textContent = 'Starting...';

    try {
        const resp = await fetch('/api/execute', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ flow_type: 'device_code_start', scope }),
        });
        const data = await resp.json();

        if (data.error) {
            showError(data.error);
            return;
        }

        const body = data.result?.response?.body;
        if (body?.verification_uri && body?.user_code) {
            deviceCodeInfo.style.display = 'block';
            deviceCodeInstructions.style.display = 'none';
            document.getElementById('device-code-url').href = body.verification_uri;
            document.getElementById('device-code-url').textContent = body.verification_uri;
            document.getElementById('device-code-value').textContent = body.user_code;
        }

        const result = data.result;
        if (result && result.steps) {
            setSteps(result.steps);
        } else {
            displayResultLegacy(result, 'device_code');
        }
        if (data.diagram) await renderMermaid(data.diagram);

        const btnPoll = document.getElementById('btn-poll');
        btnPoll.onclick = async () => {
            closeFlyout();
            btnPoll.disabled = true;
            btnPoll.textContent = 'Polling...';
            try {
                const pollResp = await fetch('/api/execute', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ flow_type: 'device_code_poll', device_code: body.device_code }),
                });
                const pollData = await pollResp.json();
                const pollResult = pollData.result;
                if (pollResult && pollResult.steps) {
                    setSteps(pollResult.steps);
                } else {
                    displayResultLegacy(pollResult, 'device_code');
                }
                updateSessionStatus();

                // Refresh highlights (may discover new subjects)
                await loadHighlights();
                if (currentSteps.length > 0) showStep(currentStepIndex);

                const pollBody = pollResult?.response?.body;
                if (pollBody?.error === 'authorization_pending') {
                    btnPoll.textContent = 'Poll Again (pending...)';
                    btnPoll.disabled = false;
                } else if (pollBody?.access_token) {
                    btnPoll.textContent = 'Token Acquired!';
                } else {
                    btnPoll.textContent = 'Poll for Token';
                    btnPoll.disabled = false;
                }
            } catch (err) {
                showError(err.message);
                btnPoll.textContent = 'Poll for Token';
                btnPoll.disabled = false;
            }
        };
    } catch (err) {
        showError(err.message);
    } finally {
        btnExecute.disabled = false;
        btnExecute.textContent = 'Start Device Code Flow';
    }
}


// ══════════════════════════════════════════════════════════════════════════
// ── LEGACY DISPLAY (fallback when no steps array) ──
// ══════════════════════════════════════════════════════════════════════════

function displayResultLegacy(result, flowType) {
    if (!result) return;
    stepTimeline.style.display = 'none';
    currentSteps = [];
    clearDiagramHighlight();
    stepPlaceholder.style.display = 'none';

    const tokens = result.tokens || {};

    if (tokens.access_token) {
        sectionAccessToken.style.display = 'block';
        setHighlightedHtml('at-header', formatJson(tokens.access_token.header));
        setHighlightedHtml('at-payload', formatJson(tokens.access_token.payload));
        document.getElementById('at-raw').value = tokens.access_token.raw || '';
    } else {
        sectionAccessToken.style.display = 'none';
    }

    if (tokens.id_token) {
        sectionIdToken.style.display = 'block';
        setHighlightedHtml('id-header', formatJson(tokens.id_token.header));
        setHighlightedHtml('id-payload', formatJson(tokens.id_token.payload));
        document.getElementById('id-raw').value = tokens.id_token.raw || '';
    } else {
        sectionIdToken.style.display = 'none';
    }

    if (tokens.refresh_token) {
        sectionRefreshToken.style.display = 'block';
        document.getElementById('refresh-token-note').textContent =
            '✓ Refresh token present — opaque to clients (not meant for introspection).';
    } else {
        sectionRefreshToken.style.display = 'none';
    }

    const req = result.request;
    if (req) {
        sectionRequest.style.display = 'block';
        const reqText = `${req.method} ${req.url}\n\nHeaders:\n${formatJson(req.headers)}\n\nBody:\n${formatJson(req.body)}`;
        setHighlightedHtml('req-display', reqText);
    } else {
        sectionRequest.style.display = 'none';
    }

    const resp = result.response;
    if (resp) {
        sectionResponse.style.display = 'block';
        const respText = `Status: ${resp.status}\n\nHeaders:\n${formatJson(resp.headers)}\n\nBody:\n${formatJson(resp.body)}`;
        setHighlightedHtml('resp-display', respText);
    } else {
        sectionResponse.style.display = 'none';
    }
}


// ── Session status ──
async function updateSessionStatus() {
    try {
        const resp = await fetch('/api/session');
        const data = await resp.json();
        const accessBadge = document.getElementById('status-access');
        const refreshBadge = document.getElementById('status-refresh');

        if (data.has_access_token) {
            accessBadge.textContent = '✓ Access token';
            accessBadge.className = 'status-badge status-has';
        } else {
            accessBadge.textContent = 'No access token';
            accessBadge.className = 'status-badge status-none';
        }
        if (data.has_refresh_token) {
            refreshBadge.textContent = '✓ Refresh token';
            refreshBadge.className = 'status-badge status-has';
        } else {
            refreshBadge.textContent = 'No refresh token';
            refreshBadge.className = 'status-badge status-none';
        }
    } catch { /* ignore */ }
}


// ── Helpers ──
function setText(id, text) {
    document.getElementById(id).textContent = text;
}

function formatJson(obj) {
    if (typeof obj === 'string') return obj;
    if (obj === null || obj === undefined) return '';
    try {
        return JSON.stringify(obj, null, 2);
    } catch {
        return String(obj);
    }
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function showError(message) {
    sectionResponse.style.display = 'block';
    setText('resp-display', `Error: ${message}`);
}


// ══════════════════════════════════════════════════════════════════════════
// ── DRAGGABLE SPLIT DIVIDER ──
// ══════════════════════════════════════════════════════════════════════════

(function initSplitDivider() {
    const splitView = document.getElementById('split-view');
    const divider = document.getElementById('split-divider');
    if (!splitView || !divider) return;

    let dragging = false;

    divider.addEventListener('mousedown', (e) => {
        e.preventDefault();
        dragging = true;
        divider.classList.add('dragging');
        document.body.style.cursor = 'col-resize';
        document.body.style.userSelect = 'none';
    });

    document.addEventListener('mousemove', (e) => {
        if (!dragging) return;
        const rect = splitView.getBoundingClientRect();
        const offset = e.clientX - rect.left;
        const total = rect.width;
        const pct = Math.min(Math.max(offset / total * 100, 15), 85);
        splitView.style.gridTemplateColumns = `${pct}% 6px ${100 - pct}%`;
    });

    document.addEventListener('mouseup', () => {
        if (!dragging) return;
        dragging = false;
        divider.classList.remove('dragging');
        document.body.style.cursor = '';
        document.body.style.userSelect = '';
    });
})();


// ── Init ──
document.addEventListener('DOMContentLoaded', async () => {
    await loadHighlights();
    loadDiagram(getDiagramKey());
    updateSessionStatus();
    updateFlowUI();

    // Check for result after Auth Code redirect
    try {
        const resp = await fetch('/api/last-result');
        const data = await resp.json();
        if (data.result) {
            const result = data.result;
            if (result.steps && result.steps.length > 0) {
                setSteps(result.steps);
            } else {
                displayResultLegacy(result, data.flow_type || 'auth_code');
            }
            if (data.diagram) await renderMermaid(data.diagram);
            if (data.flow_type) {
                const radio = document.querySelector(`input[value="${data.flow_type}"]`);
                if (radio) {
                    radio.checked = true;
                    currentFlowType = data.flow_type;
                    updateFlowUI();
                }
            }
            if (currentSteps.length > 0) highlightDiagramStep(currentStepIndex);
        }
        // Refresh highlights (subjects discovered from auth code redirect tokens)
        await loadHighlights();
        if (currentSteps.length > 0) showStep(currentStepIndex);
    } catch { /* no prior result */ }
});
