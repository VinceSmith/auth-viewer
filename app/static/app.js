/* ── Entra OAuth Explorer — Frontend Logic ── */

// ── State ──
let authCategory = 'user_auth';   // 'user_auth' | 'client_credentials'
let clientType = 'app';            // 'app' | 'agent'
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
    [45, 45, 60],
    [60, 40, 30],
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
const scopeSelect = document.getElementById('scope-select');
const btnExecute = document.getElementById('btn-execute');
const mermaidContainer = document.getElementById('mermaid-container');
const diagramHeader = document.getElementById('diagram-header');

// Flyout
const flyoutPanel = document.getElementById('flyout-panel');
const flyoutBackdrop = document.getElementById('flyout-backdrop');
const btnFlyout = document.getElementById('btn-flyout');
const btnFlyoutClose = document.getElementById('btn-flyout-close');

// Composite controls
const authCategoryRadios = document.querySelectorAll('input[name="auth_category"]');
const clientTypeRadios = document.querySelectorAll('input[name="client_type"]');
const reuseIdCheckbox = document.getElementById('reuse-id-token');
const reuseIdLabel = document.getElementById('reuse-id-label');

// Step timeline
const stepTimeline = document.getElementById('step-timeline');
const stepPills = document.getElementById('step-pills');
const stepDescription = document.getElementById('step-description');
const btnStepPrev = document.getElementById('btn-step-prev');
const btnStepNext = document.getElementById('btn-step-next');


// Detail sections
const stepPlaceholder = document.getElementById('step-placeholder');
const detailTabs = document.getElementById('detail-tabs');
const tabBar = document.getElementById('tab-bar');
const summaryContent = document.getElementById('summary-content');
const sectionRequest = document.getElementById('section-request');
const sectionResponse = document.getElementById('section-response');
const sectionAccessToken = document.getElementById('section-access-token');

let activeTab = 'summary';


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
    } catch { /* ignore */ }
}


// ══════════════════════════════════════════════════════════════════════════
// ── COMPOSITE FLOW SELECTION ──
// ══════════════════════════════════════════════════════════════════════════

// Derive the internal flow_type from the three composite controls
function isOboScope() {
    const opt = scopeSelect.options[scopeSelect.selectedIndex];
    return opt?.dataset.obo === '1';
}

function getEffectiveFlowType() {
    if (authCategory === 'client_credentials') {
        if (clientType === 'agent') return 'agent_id_autonomous';
        const scope = getScope();
        if (scope.startsWith('chain:')) return 'client_credentials_chain';
        return 'client_credentials';
    }
    // user_auth
    const obo = isOboScope();
    if (clientType === 'agent') return obo ? 'agent_id_obo' : 'agent_id_obo';
    return obo ? 'obo' : 'auth_code';
}

function getDiagramKey() {
    const ft = getEffectiveFlowType();
    if (ft === 'client_credentials_chain') {
        const scope = getScope();
        if (scope.includes('graph.microsoft.com')) return 'client_credentials_chain_graph';
    }
    return ft;
}

function getScope() {
    return scopeSelect.value;
}

function updateFlowUI() {
    const isUserAuth = authCategory === 'user_auth';

    // Client type: always enabled (no locking)
    for (const radio of clientTypeRadios) {
        radio.disabled = false;
    }

    // Stored ID token option: show for user_auth only
    reuseIdLabel.style.display = isUserAuth ? '' : 'none';

    // Filter scope options by context
    let firstVisible = null;
    let currentStillVisible = false;
    for (const opt of scopeSelect.options) {
        const ctx = (opt.dataset.ctx || '').split(' ');
        let show = false;
        if (authCategory === 'client_credentials') {
            show = ctx.includes('client_credentials') && (clientType === 'agent' ? ctx.includes('agent') : ctx.includes('app'));
        } else {
            show = ctx.includes('user_auth') && ctx.includes(clientType);
        }
        opt.hidden = !show;
        if (show && !firstVisible) firstVisible = opt;
        if (show && opt.selected) currentStillVisible = true;
    }
    if (!currentStillVisible && firstVisible) firstVisible.selected = true;

    // Button text
    if (isUserAuth && !reuseIdCheckbox?.checked) {
        btnExecute.textContent = 'Sign In & Execute';
    } else {
        btnExecute.textContent = 'Execute Flow';
    }
}

// Event listeners for composite controls
authCategoryRadios.forEach(radio => {
    radio.addEventListener('change', () => {
        authCategory = radio.value;
        setSteps([]);  // clear stale results from previous flow
        updateFlowUI();
        loadDiagram(getDiagramKey());
    });
});

clientTypeRadios.forEach(radio => {
    radio.addEventListener('change', () => {
        clientType = radio.value;
        setSteps([]);  // clear stale results from previous flow
        updateFlowUI();
        updateSessionStatus();
        loadDiagram(getDiagramKey());
    });
});

scopeSelect.addEventListener('change', () => {
    setSteps([]);
    updateFlowUI();
    updateSessionStatus();
    loadDiagram(getDiagramKey());
});

reuseIdCheckbox?.addEventListener('change', () => {
    setSteps([]);
    updateFlowUI();
    updateSessionStatus();
    loadDiagram(getDiagramKey());
});


// ══════════════════════════════════════════════════════════════════════════
// ── MERMAID DIAGRAM ──
// ══════════════════════════════════════════════════════════════════════════

function updateDiagramHeader() {
    const grantLabel = authCategory === 'user_auth' ? 'User Auth Flow' : 'Client Credentials Flow';
    const clientLabel = clientType === 'agent' ? 'Agent' : 'App';
    const selected = scopeSelect.options[scopeSelect.selectedIndex];
    const targetLabel = selected ? selected.textContent.trim() : '';
    diagramHeader.textContent = `Grant Type: ${grantLabel},  Client Type: ${clientLabel},  Target Resource: ${targetLabel}`;
    diagramHeader.style.display = '';
}

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
        detailTabs.style.display = 'none';
        stepPlaceholder.style.display = 'block';
        clearDiagramHighlight();
        return;
    }

    stepTimeline.style.display = 'block';
    activeTab = 'summary';
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
    detailTabs.style.display = 'flex';

    const req = step.request;
    const resp = step.response;
    const tokens = step.tokens || {};

    const hasRequest = !!req;
    const hasResponse = !!resp;
    const hasAccessToken = !!tokens.access_token;

    // ID token: carry forward from earlier steps if current step doesn't have one
    let idToken = tokens.id_token || null;
    if (!idToken) {
        for (let i = currentStepIndex - 1; i >= 0; i--) {
            const prev = currentSteps[i]?.tokens?.id_token;
            if (prev) { idToken = prev; break; }
        }
    }
    const hasIdToken = !!idToken;

    // Populate request tab
    if (hasRequest) {
        sectionRequest.style.display = 'block';
        document.getElementById('tab-request-empty').style.display = 'none';
        const reqText = `${req.method} ${req.url}\n\nHeaders:\n${formatJson(req.headers)}\n\nBody:\n${formatJson(req.body)}`;
        setHighlightedHtml('req-display', reqText);
    } else {
        sectionRequest.style.display = 'none';
        document.getElementById('tab-request-empty').style.display = 'block';
    }

    // Populate response tab
    if (hasResponse) {
        sectionResponse.style.display = 'block';
        document.getElementById('tab-response-empty').style.display = 'none';
        const respText = `Status: ${resp.status}\n\nHeaders:\n${formatJson(resp.headers)}\n\nBody:\n${formatJson(resp.body)}`;
        setHighlightedHtml('resp-display', respText);
    } else {
        sectionResponse.style.display = 'none';
        document.getElementById('tab-response-empty').style.display = 'block';
    }

    // Populate access token tab
    if (hasAccessToken) {
        sectionAccessToken.style.display = 'block';
        document.getElementById('tab-access-token-empty').style.display = 'none';
        setHighlightedHtml('at-header', formatJson(tokens.access_token.header));
        setHighlightedHtml('at-payload', formatJson(tokens.access_token.payload));
        document.getElementById('at-raw').value = tokens.access_token.raw || '';
    } else {
        sectionAccessToken.style.display = 'none';
        document.getElementById('tab-access-token-empty').style.display = 'block';
    }

    // Update tab badges (dim tabs with no data)
    tabBar.querySelectorAll('.tab-btn').forEach(btn => {
        const tab = btn.dataset.tab;
        let hasData = true;
        if (tab === 'request') hasData = hasRequest;
        else if (tab === 'response') hasData = hasResponse;
        else if (tab === 'access-token') hasData = hasAccessToken;
        btn.classList.toggle('tab-no-data', !hasData);
    });

    // Build summary tab
    buildSummary(step, idToken);

    // Keep current tab selection
    switchTab(activeTab);
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
    return html;
}

function setHighlightedHtml(id, text) {
    document.getElementById(id).innerHTML = highlightText(text);
}


// ══════════════════════════════════════════════════════════════════════════
// ── EXECUTE FLOW ──
// ══════════════════════════════════════════════════════════════════════════

btnExecute.addEventListener('click', async () => {
    const flowType = getEffectiveFlowType();
    const scope = getScope();

    // Close flyout on execute
    closeFlyout();

    // Update diagram header with current config
    updateDiagramHeader();

    // User auth flows — always redirect (get fresh access token)
    if (authCategory === 'user_auth') {
        const promptParam = reuseIdCheckbox?.checked ? '' : '&prompt=login';
        if (isOboScope()) {
            window.location.href = `/auth/login?flow_type=${flowType}&target_scope=${encodeURIComponent(scope)}${promptParam}`;
        } else {
            window.location.href = `/auth/login?scope=${encodeURIComponent(scope)}${promptParam}`;
        }
        return;
    }

    btnExecute.disabled = true;
    btnExecute.textContent = 'Executing...';

    try {
        const apiScope = scope.startsWith('chain:') ? scope.slice(6) : scope;
        const payload = { flow_type: flowType, scope: apiScope };
        const resp = await fetch('/api/execute', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });
        const data = await resp.json();

        if (data.error) {
            setSteps([]);  // clear stale results from previous flow
            await loadDiagram(getDiagramKey());
            if (data.error === 'token_expired') {
                showTokenExpiredError(data.message || 'Your access token has expired. Please sign in again.');
            } else {
                showError(data.message || data.error);
            }
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


// ══════════════════════════════════════════════════════════════════════════
// ── LEGACY DISPLAY (fallback when no steps array) ──
// ══════════════════════════════════════════════════════════════════════════

function displayResultLegacy(result, flowType) {
    if (!result) return;
    stepTimeline.style.display = 'none';
    currentSteps = [];
    clearDiagramHighlight();

    // Build a pseudo-step from the legacy result
    const step = {
        label: flowType,
        request: result.request || null,
        response: result.response || null,
        tokens: result.tokens || {},
    };
    populateStepDetail(step);
}


// ── Session status ──
async function updateSessionStatus() {
    try {
        const resp = await fetch('/api/session');
        const data = await resp.json();
        const accessBadge = document.getElementById('status-access');
        const idBadge = document.getElementById('status-id');
        const refreshBadge = document.getElementById('status-refresh');

        const hasToken = data.has_access_token;
        const expired = data.token_expired;

        if (hasToken && !expired) {
            accessBadge.textContent = '✓ Access token';
            accessBadge.className = 'status-badge status-has';
        } else if (hasToken && expired) {
            accessBadge.textContent = '⚠ Access token (expired)';
            accessBadge.className = 'status-badge status-expired';
        } else {
            accessBadge.textContent = 'No access token';
            accessBadge.className = 'status-badge status-none';
        }
        if (data.has_id_token) {
            idBadge.textContent = '✓ ID token';
            idBadge.className = 'status-badge status-has';
        } else {
            idBadge.textContent = 'No ID token';
            idBadge.className = 'status-badge status-none';
        }
        if (data.has_refresh_token) {
            refreshBadge.textContent = '✓ Refresh token';
            refreshBadge.className = 'status-badge status-has';
        } else {
            refreshBadge.textContent = 'No refresh token';
            refreshBadge.className = 'status-badge status-none';
        }

        // Enable/disable stored ID token checkbox
        const hasIdToken = !!data.has_id_token;

        if (reuseIdCheckbox) {
            reuseIdCheckbox.disabled = !hasIdToken;
            if (reuseIdLabel) reuseIdLabel.style.opacity = hasIdToken ? '1' : '0.4';
            // Only auto-check when newly available, don't override user's unchecking
            if (!hasIdToken) reuseIdCheckbox.checked = false;
        }

    } catch { /* ignore */ }
}


// ══════════════════════════════════════════════════════════════════════════
// ── PROFILE AVATAR & ID TOKEN PANE ──
// ══════════════════════════════════════════════════════════════════════════

let _cachedProfile = null;

function getInitials(name) {
    if (!name) return '?';
    const parts = name.trim().split(/\s+/);
    if (parts.length >= 2) return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
    return parts[0][0].toUpperCase();
}

async function loadProfile() {
    try {
        const resp = await fetch('/api/me');
        const data = await resp.json();
        if (!data.signed_in) return;
        _cachedProfile = data;

        const avatar = document.getElementById('profile-avatar');
        const initials = document.getElementById('profile-initials');
        const tooltipName = document.getElementById('tooltip-name');
        const tooltipUpn = document.getElementById('tooltip-upn');
        const tooltipOid = document.getElementById('tooltip-oid');

        const p = data.profile;
        initials.textContent = getInitials(p.name);
        tooltipName.textContent = p.name || '(no name)';
        tooltipUpn.textContent = p.preferred_username || '(no UPN)';
        tooltipOid.textContent = p.oid || '(no oid)';
        avatar.style.display = 'flex';

        // Populate the ID token pane
        if (data.id_token) {
            const paneHeader = document.getElementById('id-pane-header');
            const panePayload = document.getElementById('id-pane-payload');
            const paneRaw = document.getElementById('id-pane-raw');
            paneHeader.textContent = formatJson(data.id_token.header);
            panePayload.textContent = formatJson(data.id_token.payload);
            paneRaw.value = data.id_token_raw || '';
        }
    } catch { /* not signed in */ }
}

function openIdPane() {
    document.getElementById('id-pane').classList.add('open');
    document.getElementById('id-pane-backdrop').classList.add('open');
}

function closeIdPane() {
    document.getElementById('id-pane').classList.remove('open');
    document.getElementById('id-pane-backdrop').classList.remove('open');
}

// Wire up avatar click and pane close
document.getElementById('profile-avatar').addEventListener('click', () => {
    if (_cachedProfile) openIdPane();
});
document.getElementById('btn-id-pane-close').addEventListener('click', closeIdPane);
document.getElementById('id-pane-backdrop').addEventListener('click', closeIdPane);
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && document.getElementById('id-pane').classList.contains('open')) {
        closeIdPane();
    }
    if (e.key === 'Escape' && document.getElementById('about-pane').classList.contains('open')) {
        closeAboutPane();
    }
});

// ── About Pane ──
function openAboutPane() {
    document.getElementById('about-pane').classList.add('open');
    document.getElementById('about-pane-backdrop').classList.add('open');
}
function closeAboutPane() {
    document.getElementById('about-pane').classList.remove('open');
    document.getElementById('about-pane-backdrop').classList.remove('open');
}
document.getElementById('btn-about').addEventListener('click', openAboutPane);
document.getElementById('btn-about-close').addEventListener('click', closeAboutPane);
document.getElementById('about-pane-backdrop').addEventListener('click', closeAboutPane);


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

function parseBody(body) {
    if (body && typeof body === 'object') return body;
    if (typeof body === 'string' && body.includes('=')) {
        const obj = {};
        for (const [k, v] of new URLSearchParams(body)) obj[k] = v;
        return obj;
    }
    return {};
}

function resolveGuid(value) {
    const s = String(value);
    if (highlightMap[s]) return highlightMap[s].label;
    return s;
}

function resolveGuidsInString(str) {
    let s = String(str);
    for (const [guid, info] of Object.entries(highlightMap)) {
        if (s.includes(guid)) s = s.replaceAll(guid, info.label);
    }
    return s;
}

function resolveGuidsDeep(obj) {
    if (typeof obj === 'string') return resolveGuidsInString(obj);
    if (Array.isArray(obj)) return obj.map(resolveGuidsDeep);
    if (obj && typeof obj === 'object') {
        const out = {};
        for (const [k, v] of Object.entries(obj)) out[k] = resolveGuidsDeep(v);
        return out;
    }
    return obj;
}

function summarizeResponseBody(body) {
    if (!body) return '';
    if (typeof body === 'string') return resolveGuidsInString(body);
    if (body.message) return resolveGuidsInString(body.message);
    if (body.error_description) return resolveGuidsInString(body.error_description);
    if (body.error) return typeof body.error === 'string' ? resolveGuidsInString(body.error) : JSON.stringify(body.error);
    // Filter out expiry claims and replace token values with readable names
    const filtered = {};
    const tokenKeys = { access_token: '[access token]', id_token: '[id token]' };
    const skipKeys = new Set(['expires_in', 'ext_expires_in', 'not_before', 'refresh_token']);
    for (const [k, v] of Object.entries(body)) {
        if (skipKeys.has(k)) continue;
        if (tokenKeys[k]) { filtered[k] = tokenKeys[k]; continue; }
        filtered[k] = resolveGuidsDeep(v);
    }
    try { return JSON.stringify(filtered, null, 2); } catch { return String(body); }
}

function _linkifyTokenPlaceholders(html) {
    return html
        .replace(/\[access token\]/g, '<a href="#" class="token-link" onclick="switchTab(\'access-token\');return false">[access token]</a>')
        .replace(/\[user token\]/g, '<a href="#" class="token-link" onclick="openIdPane();return false">[user token]</a>');
}

function httpStatusText(code) {
    const map = { 200: 'OK', 201: 'Created', 204: 'No Content', 301: 'Moved Permanently', 302: 'Found',
        400: 'Bad Request', 401: 'Unauthorized', 403: 'Forbidden', 404: 'Not Found', 405: 'Method Not Allowed',
        500: 'Internal Server Error', 502: 'Bad Gateway', 503: 'Service Unavailable' };
    return map[code] || '';
}

function showError(message) {
    detailTabs.style.display = 'flex';
    stepPlaceholder.style.display = 'none';
    sectionResponse.style.display = 'block';
    document.getElementById('tab-response-empty').style.display = 'none';
    setText('resp-display', `Error: ${message}`);
    switchTab('response');
}

function showTokenExpiredError(message) {
    detailTabs.style.display = 'flex';
    stepPlaceholder.style.display = 'none';
    sectionResponse.style.display = 'block';
    document.getElementById('tab-response-empty').style.display = 'none';
    const container = document.getElementById('resp-display');
    const scope = getScope();
    const flowType = getEffectiveFlowType();
    container.innerHTML = `<div class="error-banner" style="margin:0">`
        + `<p style="margin:0 0 10px 0">${escapeHtml(message)}</p>`
        + `<button class="btn btn-primary" onclick="window.location.href='/auth/login?flow_type=${encodeURIComponent(flowType)}&target_scope=${encodeURIComponent(scope)}&prompt=login'">Sign In Again</button>`
        + `</div>`;
    switchTab('response');
    updateSessionStatus();
}


// ══════════════════════════════════════════════════════════════════════════
// ── TAB SWITCHING ──
// ══════════════════════════════════════════════════════════════════════════

function switchTab(tabName) {
    activeTab = tabName;
    tabBar.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.tab === tabName);
    });
    document.querySelectorAll('.tab-pane').forEach(pane => {
        pane.classList.toggle('active', pane.id === `tab-${tabName}`);
    });
}

tabBar.addEventListener('click', (e) => {
    const btn = e.target.closest('.tab-btn');
    if (btn) switchTab(btn.dataset.tab);
});


// ══════════════════════════════════════════════════════════════════════════
// ── SUMMARY TAB BUILDER ──
// ══════════════════════════════════════════════════════════════════════════

function buildSummary(step, idToken) {
    const req = step.request;
    const resp = step.response;
    const tokens = step.tokens || {};

    let html = '';

    // Request summary — filtered body with resolved names
    if (req) {
        html += '<div class="summary-section">';
        html += '<h5 class="summary-heading"><a href="#" class="token-link" onclick="switchTab(\'request\');return false">Request</a></h5>';
        let bodyLines = '';
        const bodyObj = parseBody(req.body);
        const skipReqKeys = new Set(['client_secret', 'code', 'redirect_uri']);
        const tokenReqKeys = {
            client_assertion: '[parent token (Blueprint)]',
            assertion: '[user token]',
        };
        for (const [key, val] of Object.entries(bodyObj)) {
            if (skipReqKeys.has(key)) continue;
            const display = tokenReqKeys[key] || resolveGuidsInString(val);
            bodyLines += `\n  ${key}: ${display}`;
        }
        const reqSummary = `${req.method} ${req.url}${bodyLines}`;
        html += `<pre class="code-block">${_linkifyTokenPlaceholders(escapeHtml(reqSummary))}</pre>`;
        html += '</div>';
    }

    // Response summary
    if (resp) {
        html += '<div class="summary-section">';
        html += '<h5 class="summary-heading"><a href="#" class="token-link" onclick="switchTab(\'response\');return false">Response</a></h5>';
        const statusCode = typeof resp.status === 'number' ? resp.status : parseInt(resp.status, 10);
        if (statusCode >= 200 && statusCode < 300 && resp.body) {
            // Success — show the returned data
            const bodyStr = summarizeResponseBody(resp.body);
            html += `<pre class="code-block">${_linkifyTokenPlaceholders(escapeHtml(bodyStr))}</pre>`;
        } else {
            // Failure — show status code and message
            const statusMsg = statusCode ? `${statusCode} ${httpStatusText(statusCode)}` : String(resp.status);
            let detail = statusMsg;
            if (resp.body) {
                const errStr = summarizeResponseBody(resp.body);
                if (errStr) detail += `\n${errStr}`;
            }
            html += `<pre class="code-block">${escapeHtml(detail)}</pre>`;
        }
        html += '</div>';
    }

    // Access token key claims
    if (tokens.access_token && tokens.access_token.payload) {
        html += buildClaimsSection('<a href="#" class="token-link" onclick="switchTab(\'access-token\');return false">Access Token</a>', tokens.access_token.payload, ['sub', 'azp', 'scp', 'appid', 'aud']);
    }

    // ID token key claims
    if (idToken && idToken.payload) {
        html += buildClaimsSection('ID Token', idToken.payload, ['sub', 'preferred_username', 'tid', 'azp', 'scp', 'appid', 'aud']);
    }

    if (!html) {
        html = '<p class="tab-empty">Display-only step — see the description above.</p>';
    }

    summaryContent.innerHTML = html;
}

function buildClaimsSection(title, payload, claimKeys) {
    const claims = [];
    for (const key of claimKeys) {
        if (payload[key] !== undefined && payload[key] !== null) {
            claims.push({ key, value: payload[key] });
        }
    }
    if (claims.length === 0) return '';

    let html = '<div class="summary-section">';
    html += `<h5 class="summary-heading">${title}</h5>`;
    html += '<table class="claims-table"><tbody>';
    for (const { key, value } of claims) {
        const desc = CLAIM_DESCRIPTIONS[key] || '';
        const resolved = resolveClaimValue(key, value);
        html += '<tr>';
        html += `<td class="claim-name" title="${escapeHtml(desc)}">${escapeHtml(key)}</td>`;
        html += `<td class="claim-value">${resolved}</td>`;
        html += '</tr>';
    }
    html += '</tbody></table>';
    html += '</div>';
    return html;
}

function resolveClaimValue(key, value) {
    const strVal = String(value);
    // scp is a space-separated list of scope names, not GUIDs
    if (key === 'scp') return escapeHtml(strVal);
    // For known IDs, show human-readable label with raw value on hover
    if (highlightMap[strVal]) {
        const label = highlightMap[strVal].label;
        return `<span class="claim-resolved" title="${escapeHtml(strVal)}">${escapeHtml(label)}</span>`;
    }
    // tid: show the GUID as-is if no friendly name
    return escapeHtml(strVal);
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
    // Pulse the info icon only on the very first page load (not after auth redirects)
    if (!sessionStorage.getItem('visited')) {
        sessionStorage.setItem('visited', '1');
        document.getElementById('btn-about')?.classList.add('intro-pulse');
    }

    await loadHighlights();
    loadDiagram(getDiagramKey());
    updateSessionStatus();
    loadProfile();
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
            // Restore composite controls from the returned flow_type
            if (data.flow_type) {
                const ft = data.flow_type;
                if (ft === 'client_credentials' || ft === 'client_credentials_chain') {
                    authCategory = 'client_credentials'; clientType = 'app';
                } else if (ft === 'agent_id_autonomous') {
                    authCategory = 'client_credentials'; clientType = 'agent';
                } else if (ft === 'obo') {
                    authCategory = 'user_auth'; clientType = 'app';
                } else if (ft === 'agent_id_obo') {
                    authCategory = 'user_auth'; clientType = 'agent';
                } else {
                    authCategory = 'user_auth'; clientType = 'app';
                }
                // Sync radio buttons
                const acRadio = document.querySelector(`input[name="auth_category"][value="${authCategory}"]`);
                if (acRadio) acRadio.checked = true;
                const ctRadio = document.querySelector(`input[name="client_type"][value="${clientType}"]`);
                if (ctRadio) ctRadio.checked = true;
                updateFlowUI();
                // Select the OBO scope option if the flow was OBO
                if (ft === 'obo' || ft === 'agent_id_obo') {
                    for (const opt of scopeSelect.options) {
                        if (!opt.hidden && opt.dataset.obo === '1') {
                            opt.selected = true;
                            break;
                        }
                    }
                }
                updateSessionStatus();
                updateDiagramHeader();
            }
            if (currentSteps.length > 0) highlightDiagramStep(currentStepIndex);
        }
        // Refresh highlights (subjects discovered from auth code redirect tokens)
        await loadHighlights();
        if (currentSteps.length > 0) showStep(currentStepIndex);
        // Refresh profile avatar (new ID token may have arrived)
        loadProfile();
    } catch { /* no prior result */ }
});
