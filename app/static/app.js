/* ── Entra OAuth Explorer — Frontend Logic ── */

// ── State ──
var authCategory = 'user_auth';   // 'user_auth' | 'client_credentials'
var clientType = 'app';            // 'app' | 'agent'
var diagramCounter = 0;
var currentSteps = [];
var currentStepIndex = 0;
var currentFlowType = '';
var highlightMap = {};
var diagramStepRects = [];

// Sign-in log polling state
let signinLogTimer = null;
let signinLogAfter = null;
let signinLogEntries = [];     // full Graph entries (delayed)
let signinLogPreviews = [];    // instant preview entries extracted from step responses
let signinLogCountdown = 0;
let signinLogMaxTime = 600;  // stop auto-polling after 10 minutes
let signinLogElapsed = 0;

// Step rect fill colors — injected from diagrams.py via base.html template.
// Do NOT hardcode this here; edit STEP_FILLS in app/diagrams.py instead.
// (const STEP_FILLS is set by the inline <script> in base.html)

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
    azpacr: 'Authorized party auth method. Values: 0 = public client (no secret), 1 = client secret, 2 = certificate',
    appid: 'Application ID — client_id (v1 tokens)',
    appidacr: 'Application auth method (v1). Values: 0 = public, 1 = secret, 2 = certificate',
    idtyp: 'Token identity type. Values: "app" (app-only/client credentials), absent = delegated (user context)',
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
    acr: 'Authentication context class reference. Values: "0" = no MFA, "1" = MFA satisfied',
    amr: 'Authentication methods used. Values: "pwd" (password), "mfa" (multi-factor), "rsa" (certificate), "otp" (one-time passcode), "fido" (FIDO2 key)',
    auth_time: 'Time when the user last authenticated',
    login_hint: 'Opaque hint for seamless re-authentication',
    sid: 'Session ID for single sign-out',
    tenant_region_scope: 'Region of the tenant (e.g. NA, EU)',
    // Token exchange
    act: 'Actor — the entity acting on behalf of the subject',
    client_id: 'Client ID that requested this token',
    // OIDC
    ver: 'Token version. Values: "1.0" (v1 endpoint), "2.0" (v2 endpoint / MSAL)',
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

// OIDC discovery document property descriptions (hover tooltips on summary tab)
const OIDC_PROPERTY_DESCRIPTIONS = {
    authorization_endpoint: 'URL where the client redirects the user to sign in and consent',
    token_endpoint: 'URL where the client exchanges a grant (code, assertion, credentials) for tokens',
    issuer: 'The "iss" claim value — must match this in every token the client validates',
    jwks_uri: 'URL of the JSON Web Key Set — public keys used to verify token signatures',
    userinfo_endpoint: 'URL to retrieve claims about the authenticated user (rarely used with Entra)',
    response_types_supported: 'OAuth response types this server supports (e.g. code, id_token)',
    scopes_supported: 'Scopes the authorization server advertises (e.g. openid, profile, email)',
};

// Request parameter descriptions (label + hover description)
const PARAM_DESCRIPTIONS = {
    client_id: {
        label: 'Application',
        desc: 'The application (client) ID assigned during app registration',
    },
    response_type: {
        label: 'Response Type',
        desc: 'What the app expects back. Values: "code" (authorization code), "token" (implicit), "id_token" (OIDC implicit), "code id_token" (hybrid)',
    },
    redirect_uri: {
        label: 'Callback URL',
        desc: 'Where Entra ID sends the user after authentication. Must exactly match a URI registered on the app',
    },
    scope: {
        label: 'Permissions',
        desc: 'Space-separated permissions requested. Common: "openid" (sign-in), "profile" (name/email), "offline_access" (refresh token), or API scopes like "api://{id}/access_as_user"',
    },
    response_mode: {
        label: 'Response Mode',
        desc: 'How the result is returned. Values: "query" (URL query string), "fragment" (URL hash), "form_post" (HTTP POST body)',
    },
    prompt: {
        label: 'Prompt',
        desc: 'Controls the sign-in experience. Values: "login" (force re-auth), "consent" (force consent), "select_account" (account picker), "none" (silent, fail if interaction needed)',
    },
    grant_type: {
        label: 'Grant Type',
        desc: 'The OAuth 2.0 grant being used. Values: "authorization_code", "client_credentials", "urn:ietf:params:oauth:grant-type:jwt-bearer" (OBO), "urn:ietf:params:oauth:grant-type:token-exchange" (Agent ID)',
    },
    client_assertion_type: {
        label: 'Assertion Type',
        desc: 'Format of the client_assertion. Typically "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" (signed JWT)',
    },
    client_assertion: {
        label: 'Client Assertion',
        desc: 'A signed JWT used to authenticate the client instead of a client_secret (used in certificate-based and token exchange flows)',
    },
    assertion: {
        label: 'Assertion',
        desc: 'The access token being exchanged. In SP OBO this is the user\'s token; in Agent ID this may be the user\'s token or the agent\'s token depending on the step',
    },
    requested_token_use: {
        label: 'Token Use',
        desc: 'How the assertion should be used. Values: "on_behalf_of" (exchange a user token for a new one with different audience)',
    },
    subject_token: {
        label: 'Subject Token',
        desc: 'The token representing the subject of the exchange (used in token exchange / Agent ID flows)',
    },
    subject_token_type: {
        label: 'Subject Token Type',
        desc: 'Type of the subject token. Typically "urn:ietf:params:oauth:token-type:jwt"',
    },
    actor_token: {
        label: 'Actor Token',
        desc: 'Token representing the actor (the entity acting on behalf of the subject) in a token exchange',
    },
    actor_token_type: {
        label: 'Actor Token Type',
        desc: 'Type of the actor token. Typically "urn:ietf:params:oauth:token-type:jwt"',
    },
    state: {
        label: 'State (CSRF)',
        desc: 'A random value generated by the client and included in the /authorize request. Entra returns it unchanged in the callback. The client MUST verify it matches to prevent authorization code injection (CSRF) attacks',
    },
    client_secret: {
        label: 'Client Secret',
        desc: 'The app\'s password (confidential client credential). In production, prefer certificates or managed identity. Never expose this in client-side code',
    },
    refresh_token: {
        label: 'Refresh Token',
        desc: 'An opaque token from a prior sign-in. Exchanged for a new access token without user interaction. Refresh tokens are audience-agnostic — they can be redeemed for any API the client has permission to access',
    },
    fmi_path: {
        label: 'FMI Path (Agent Identity)',
        desc: 'The object ID of the Agent Identity (BlueprintPrincipal). Tells Entra which agent to scope the parent token to',
    },
    code: {
        label: 'Authorization Code',
        desc: 'The one-time code returned by /authorize after user authentication. Exchanged at the /token endpoint for access + ID tokens. Valid for ~10 minutes, single-use',
    },
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
const stepContextBanner = document.getElementById('step-context-banner');
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
const sectionReqToken = document.getElementById('section-req-token');
const sectionRespToken = document.getElementById('section-resp-token');

// Sign-in log elements
const signinLogToolbar = document.getElementById('signin-log-toolbar');
const signinLogCountdownEl = document.getElementById('signin-log-countdown');
const tabSigninLogBtn = document.querySelector('.tab-btn[data-tab="signin-log"]');
const signinLogContent = document.getElementById('signin-log-content');
const signinLogEmpty = document.getElementById('tab-signin-log-empty');
const btnSigninLogFetch = document.getElementById('btn-signin-log-fetch');

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
        const scope = getScope();
        if (clientType === 'agent') {
            if (scope.startsWith('chain:')) return 'agent_id_autonomous_chain';
            return 'agent_id_autonomous';
        }
        if (scope.startsWith('chain:')) return 'client_credentials_chain';
        return 'client_credentials';
    }
    // user_auth
    const obo = isOboScope();
    if (clientType === 'agent') return 'agent_id_obo';
    return obo ? 'obo' : 'auth_code';
}

function getDiagramKey() {
    const ft = getEffectiveFlowType();
    if (ft === 'client_credentials_chain' || ft === 'agent_id_autonomous_chain') {
        const scope = getScope();
        if (scope.includes('graph.microsoft.com')) return ft + '_graph';
    }
    return ft;
}

function getScope() {
    return scopeSelect.value;
}

function getChainTarget() {
    const opt = scopeSelect.options[scopeSelect.selectedIndex];
    return opt?.dataset.chain || '';
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
        updateFlowUI();
    });
});

clientTypeRadios.forEach(radio => {
    radio.addEventListener('change', () => {
        clientType = radio.value;
        updateFlowUI();
        updateSessionStatus();
    });
});

scopeSelect.addEventListener('change', () => {
    updateFlowUI();
    updateSessionStatus();
});

reuseIdCheckbox?.addEventListener('change', () => {
    updateFlowUI();
    updateSessionStatus();
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

    // Hide context banner when switching to a new flow
    if (stepContextBanner) stepContextBanner.style.display = 'none';

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

    // Highlight corresponding diagram rect using explicit diagram_index when available.
    // diagram_index === -1 means no rect (e.g. OIDC Discovery, Token Handoff) — clear.
    const diagIdx = (step.diagram_index !== undefined) ? step.diagram_index : index;
    if (diagIdx < 0) {
        clearDiagramHighlight();
    } else {
        highlightDiagramStep(diagIdx);
    }
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

    // Determine whether the access token belongs to the request or response tab.
    // If the response body contains an access_token field, it was returned by a token endpoint.
    // Otherwise (e.g. "Call Resource" or "Input Token" steps) it's the token used in the request.
    const isResponseToken = hasAccessToken && resp && resp.body && resp.body.access_token;
    const isRequestToken = hasAccessToken && !isResponseToken;

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
        document.getElementById('tab-request-empty').style.display = isRequestToken ? 'none' : 'block';
    }

    // Access token on request tab (token sent in the request)
    if (isRequestToken) {
        sectionReqToken.style.display = 'block';
        setHighlightedHtml('req-at-header', formatJson(tokens.access_token.header));
        setHighlightedHtml('req-at-payload', formatJson(tokens.access_token.payload));
        document.getElementById('req-at-raw').value = tokens.access_token.raw || '';
    } else {
        sectionReqToken.style.display = 'none';
    }

    // Assertion token on request tab (parent token used as client_assertion)
    const sectionReqAssertion = document.getElementById('section-req-assertion');
    if (tokens.assertion_token?.payload) {
        sectionReqAssertion.style.display = 'block';
        setHighlightedHtml('req-assertion-header', formatJson(tokens.assertion_token.header));
        setHighlightedHtml('req-assertion-payload', formatJson(tokens.assertion_token.payload));
        document.getElementById('req-assertion-raw').value = tokens.assertion_token.raw || '';
    } else {
        sectionReqAssertion.style.display = 'none';
    }

    // User assertion token on request tab (user token used as OBO assertion)
    const sectionReqUserAssertion = document.getElementById('section-req-user-assertion');
    if (tokens.user_assertion_token?.payload) {
        sectionReqUserAssertion.style.display = 'block';
        setHighlightedHtml('req-user-assertion-header', formatJson(tokens.user_assertion_token.header));
        setHighlightedHtml('req-user-assertion-payload', formatJson(tokens.user_assertion_token.payload));
        document.getElementById('req-user-assertion-raw').value = tokens.user_assertion_token.raw || '';
    } else {
        sectionReqUserAssertion.style.display = 'none';
    }

    // Populate response tab
    if (hasResponse) {
        sectionResponse.style.display = 'block';
        document.getElementById('tab-response-empty').style.display = 'none';
        let respText = `Status: ${resp.status}\n\nHeaders:\n${formatJson(resp.headers)}\n\nBody:\n${formatJson(resp.body)}`;
        setHighlightedHtml('resp-display', respText);
    } else {
        sectionResponse.style.display = 'none';
        document.getElementById('tab-response-empty').style.display = 'block';
    }

    // ID token on response tab (only for profile_login Token Exchange)
    const sectionRespIdToken = document.getElementById('section-resp-id-token');
    const stepIdToken = tokens.id_token;
    if (currentFlowType === 'profile_login' && stepIdToken?.payload && isResponseToken) {
        sectionRespIdToken.style.display = 'block';
        setHighlightedHtml('resp-id-header', formatJson(stepIdToken.header));
        setHighlightedHtml('resp-id-payload', formatJson(stepIdToken.payload));
        document.getElementById('resp-id-raw').value = stepIdToken.raw || '';
    } else {
        sectionRespIdToken.style.display = 'none';
    }

    // Access token on response tab (token returned in the response)
    if (isResponseToken) {
        sectionRespToken.style.display = 'block';
        setHighlightedHtml('resp-at-header', formatJson(tokens.access_token.header));
        setHighlightedHtml('resp-at-payload', formatJson(tokens.access_token.payload));
        document.getElementById('resp-at-raw').value = tokens.access_token.raw || '';
    } else {
        sectionRespToken.style.display = 'none';
    }

    // Populate redirect URL tab (only for Authorize Redirect steps)
    const hasRedirectUrl = !!step.authorize_url;
    const redirectTab = tabBar.querySelector('.tab-btn[data-tab="redirect"]');
    if (hasRedirectUrl) {
        const decoded = decodeURIComponent(step.authorize_url);
        setHighlightedHtml('redirect-url-display', decoded);
        if (redirectTab) redirectTab.style.display = '';
    } else {
        if (redirectTab) redirectTab.style.display = 'none';
    }

    // Populate sign-in log tab for this step
    const stepCorrId = (resp && resp.headers) ? (resp.headers['x-ms-request-id'] || '') : '';
    const hasSigninLog = renderSigninLogForStep(stepCorrId);

    // Update tab badges (dim tabs with no data)
    tabBar.querySelectorAll('.tab-btn').forEach(btn => {
        const tab = btn.dataset.tab;
        let hasData = true;
        if (tab === 'request') hasData = hasRequest || isRequestToken;
        else if (tab === 'redirect') hasData = hasRedirectUrl;
        else if (tab === 'response') hasData = hasResponse || isResponseToken;
        else if (tab === 'signin-log') hasData = hasSigninLog;
        btn.classList.toggle('tab-no-data', !hasData);
    });

    // Build summary tab
    buildSummary(step, idToken, isRequestToken, isResponseToken);

    // Keep current tab selection (fall back to summary if redirect tab hidden)
    if (activeTab === 'redirect' && !hasRedirectUrl) {
        switchTab('summary');
    } else {
        switchTab(activeTab);
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
    currentFlowType = flowType;
    const scope = getScope();
    const chainTarget = getChainTarget();

    // Close flyout on execute
    closeFlyout();

    // Update diagram header with current config
    updateDiagramHeader();

    // User auth flows
    if (authCategory === 'user_auth') {
        sessionStorage.setItem('flow_start_time', new Date().toISOString());

        // Try silent acquire first when the checkbox is checked (reuse stored session).
        // After sign-in, the checkbox auto-checks — uncheck it to force a new sign-in.
        // Falls through to full redirect if silent acquire fails.
        if (reuseIdCheckbox?.checked) {
            btnExecute.disabled = true;
            btnExecute.textContent = 'Acquiring token...';
            let silentOk = false;
            try {
                const silentScope = `openid profile offline_access ${scope}`;
                const silentResp = await fetch('/api/silent-acquire', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ scope: silentScope, flow_type: flowType }),
                });
                const silentData = await silentResp.json();
                if (!silentData.error && silentData.access_token) {
                    // Success — now execute the flow with the acquired token
                    const execPayload = { flow_type: flowType, scope: scope, chain_target: chainTarget };
                    const execResp = await fetch('/api/execute', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(execPayload),
                    });
                    const execData = await execResp.json();
                    if (execData.error) {
                        // Execute failed after silent token — show error, don't redirect
                        setSteps([]);
                        await loadDiagram(getDiagramKey());
                        if (execData.error === 'token_expired') {
                            showTokenExpiredError(execData.message || 'Your access token has expired. Please sign in again.');
                        } else {
                            showError(execData.message || execData.error);
                        }
                        silentOk = true;  // prevent fallthrough to redirect
                    } else {
                        const result = execData.result;
                        if (result && result.steps && result.steps.length > 0) {
                            setSteps(result.steps);
                        } else {
                            displayResultLegacy(result, flowType);
                        }
                        if (execData.diagram) {
                            await renderMermaid(execData.diagram);
                        } else {
                            await loadDiagram(getDiagramKey());
                        }
                        if (currentSteps.length > 0) highlightDiagramStep(currentStepIndex);
                        updateSessionStatus();
                        await loadHighlights();
                        if (currentSteps.length > 0) showStep(currentStepIndex);
                        startSigninLogPolling(sessionStorage.getItem('flow_start_time'));
                        silentOk = true;
                    }
                }
            } catch { /* fall through to redirect */ }
            btnExecute.disabled = false;
            updateFlowUI();
            if (silentOk) return;
        }

        // Full redirect through Entra /authorize
        const promptParam = reuseIdCheckbox?.checked ? '' : '&prompt=login';
        const chainParam = chainTarget ? `&chain_target=${chainTarget}` : '';
        if (isOboScope() || clientType === 'agent') {
            window.location.href = `/auth/login?flow_type=${flowType}&target_scope=${encodeURIComponent(scope)}${chainParam}${promptParam}`;
        } else {
            window.location.href = `/auth/login?scope=${encodeURIComponent(scope)}${promptParam}`;
        }
        return;
    }

    btnExecute.disabled = true;
    btnExecute.textContent = 'Executing...';
    const flowStartTime = new Date().toISOString();

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

        // Use diagram variant returned by server (handles _cached / _silent paths)
        if (data.diagram) {
            await renderMermaid(data.diagram);
        } else {
            await loadDiagram(getDiagramKey());
        }
        if (currentSteps.length > 0) highlightDiagramStep(currentStepIndex);
        updateSessionStatus();
        await loadHighlights();
        // Re-render current step with updated highlights
        if (currentSteps.length > 0) showStep(currentStepIndex);
        startSigninLogPolling(flowStartTime);
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
        const idBadge = document.getElementById('status-id');
        const refreshBadge = document.getElementById('status-refresh');

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
            const wasDisabled = reuseIdCheckbox.disabled;
            reuseIdCheckbox.disabled = !hasIdToken;
            if (reuseIdLabel) reuseIdLabel.style.opacity = hasIdToken ? '1' : '0.4';
            // Auto-check when first sign-in completes (was disabled → now enabled)
            if (hasIdToken && wasDisabled) {
                reuseIdCheckbox.checked = true;
                updateFlowUI();
            }
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

// Sign out button (in ID pane)
document.getElementById('btn-signout').addEventListener('click', async () => {
    await fetch('/auth/logout');
    window.location.reload();
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

function resolveGuidsWithOriginal(str) {
    let s = String(str);
    for (const [guid, info] of Object.entries(highlightMap)) {
        if (s.includes(guid)) s = s.replaceAll(guid, `${info.label} (${guid})`);
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

    // OIDC discovery — brief summary of key endpoints
    if (body.authorization_endpoint && body.token_endpoint) {
        // Extract tenant ID from the endpoints themselves (GUID in the URL path)
        const shorten = (url) => {
            if (!url) return url;
            const m = url.match(/\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/);
            if (!m) return url;
            const idx = url.indexOf('/' + m[1]);
            return url.slice(idx).replace(m[1], '[Tenant ID]');
        };
        const lines = [];
        if (body.authorization_endpoint) lines.push(`authorize: ${shorten(body.authorization_endpoint)}`);
        if (body.token_endpoint) lines.push(`token:     ${shorten(body.token_endpoint)}`);
        if (body.jwks_uri) lines.push(`jwks:      ${shorten(body.jwks_uri)}`);
        if (body.issuer) lines.push(`issuer:    ${shorten(body.issuer)}`);
        return lines.join('\n');
    }

    // Graph /organization — show just key org info
    if (body.value && Array.isArray(body.value) && body.value[0]?.displayName && body.value[0]?.id) {
        const org = body.value[0];
        const pick = ['displayName', 'city', 'state', 'country', 'postalCode', 'street',
                       'preferredLanguage', 'tenantType'];
        const filtered = {};
        for (const k of pick) {
            if (org[k] !== undefined && org[k] !== null) filtered[k] = resolveGuidsDeep(org[k]);
        }
        try { return JSON.stringify(filtered, null, 2); } catch { return ''; }
    }

    // Filter out expiry claims and replace token values with readable names
    const filtered = {};
    const tokenKeys = { access_token: '[access token]' };
    const skipKeys = new Set(['expires_in', 'ext_expires_in', 'not_before', 'refresh_token', 'id_token']);
    for (const [k, v] of Object.entries(body)) {
        if (skipKeys.has(k)) continue;
        if (tokenKeys[k]) { filtered[k] = tokenKeys[k]; continue; }
        filtered[k] = resolveGuidsDeep(v);
    }
    try { return JSON.stringify(filtered, null, 2); } catch { return String(body); }
}

function _linkifyTokenPlaceholders(html) {
    return html
        .replace(/\[access_token\]/g, '<a href="#" class="token-link" onclick="switchTab(\'request\');return false">[access_token]</a>')
        .replace(/\[access token\]/g, '<a href="#" class="token-link" onclick="switchTab(\'response\');return false">[access token]</a>')
        .replace(/\[assertion\]/g, '<a href="#" class="token-link" onclick="switchTab(\'request\');return false">[assertion]</a>')
        .replace(/\[authorization_code\]/g, '<a href="#" class="token-link" onclick="switchTab(\'request\');return false">[authorization_code]</a>')
        .replace(/\[id token\]/g, '<a href="#" class="token-link" onclick="openIdPane();return false">[id token]</a>');
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

// Key claims worth surfacing on the summary tab
const SUMMARY_ACCESS_TOKEN_CLAIMS = [
    'aud', 'iss', 'azp', 'appid', 'idtyp',
    'scp', 'roles', 'sub', 'oid', 'tid',
    'upn', 'fmi_path', 'exp',
];

const SUMMARY_ID_TOKEN_CLAIMS = [
    'sub', 'name', 'preferred_username', 'email',
    'oid', 'tid', 'iss', 'aud', 'nonce', 'exp',
];

function buildSummary(step, idToken, isRequestToken, isResponseToken) {
    const req = step.request;
    const resp = step.response;
    const tokens = step.tokens || {};

    let html = '';

    // Request summary — as a table with hover descriptions
    if (req || isRequestToken) {
        html += '<div class="summary-section">';
        html += '<h5 class="summary-heading"><a href="#" class="token-link" onclick="switchTab(\'request\');return false">Request</a></h5>';
        if (req) {
            // Friendly display: strip query params and shorten known API URLs
            let displayUrl = req.url.split('?')[0];
            if (displayUrl.includes('localhost:8001') || displayUrl.includes('127.0.0.1:8001'))
                displayUrl = displayUrl.replace(/https?:\/\/(localhost|127\.0\.0\.1):8001/, 'API A');
            else if (displayUrl.includes('localhost:8002') || displayUrl.includes('127.0.0.1:8002'))
                displayUrl = displayUrl.replace(/https?:\/\/(localhost|127\.0\.0\.1):8002/, 'API B');
            else if (/\/\/api-a[.-]/.test(displayUrl))
                displayUrl = displayUrl.replace(/https?:\/\/[^/]+/, 'API A');
            else if (/\/\/api-b[.-]/.test(displayUrl))
                displayUrl = displayUrl.replace(/https?:\/\/[^/]+/, 'API B');
            html += `<div class="summary-endpoint">${escapeHtml(req.method)} ${escapeHtml(displayUrl)}</div>`;
            const bodyObj = parseBody(req.body);
            const skipReqKeys = new Set(['refresh_token']);
            const tokenReqKeys = {
                client_assertion: '[parent token (Blueprint)]',
                assertion: '[assertion]',
                code: '[authorization_code]',
            };
            const rows = [];
            for (const [key, val] of Object.entries(bodyObj)) {
                if (skipReqKeys.has(key)) continue;
                let display;
                if (tokenReqKeys[key]) {
                    display = tokenReqKeys[key];
                } else if (key === 'fmi_path' && highlightMap[val]) {
                    // Show human-readable name with GUID for agent identity
                    display = `${highlightMap[val].label} (${val})`;
                } else {
                    display = resolveGuidsWithOriginal(val);
                }
                const info = PARAM_DESCRIPTIONS[key] || {};
                rows.push({ key, display, label: info.label || key, desc: info.desc || '' });
            }
            if (rows.length > 0) {
                html += '<table class="claims-table"><tbody>';
                for (const { key, display, label, desc } of rows) {
                    html += '<tr>';
                    html += `<td class="claim-name">${escapeHtml(label)}${desc ? `<span class="claim-tip">${escapeHtml(desc)}</span>` : ''}</td>`;
                    html += `<td class="claim-value">${_linkifyTokenPlaceholders(escapeHtml(display))}</td>`;
                    html += '</tr>';
                }
                html += '</tbody></table>';
            }
        }

        // Show key claims from the access token used in the request
        if (isRequestToken && tokens.access_token?.payload) {
            html += buildClaimsSection('Access Token Claims', tokens.access_token.payload, SUMMARY_ACCESS_TOKEN_CLAIMS);
        }
        html += '</div>';
    }

    // Response summary
    if (resp) {
        html += '<div class="summary-section">';
        html += '<h5 class="summary-heading"><a href="#" class="token-link" onclick="switchTab(\'response\');return false">Response</a></h5>';
        const statusCode = typeof resp.status === 'number' ? resp.status : parseInt(resp.status, 10);
        if (statusCode >= 200 && statusCode < 300 && resp.body) {
            // OIDC discovery — render as a table with hover tooltips
            if (resp.body.authorization_endpoint && resp.body.token_endpoint) {
                html += buildOidcDiscoverySummary(resp.body);
            } else {
                // Success — show the returned data
                const bodyStr = summarizeResponseBody(resp.body);
                html += `<pre class="code-block">${_linkifyTokenPlaceholders(escapeHtml(bodyStr))}</pre>`;
            }
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
        // Show key claims from the access token returned in the response
        if (currentFlowType === 'profile_login' && tokens.id_token?.payload) {
            html += buildClaimsSection('ID Token Claims', tokens.id_token.payload, SUMMARY_ID_TOKEN_CLAIMS);
        }
        if (isResponseToken && tokens.access_token?.payload) {
            html += buildClaimsSection('Access Token Claims', tokens.access_token.payload, SUMMARY_ACCESS_TOKEN_CLAIMS);
        }
        html += '</div>';
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
        html += `<td class="claim-name">${escapeHtml(key)}${desc ? `<span class="claim-tip">${escapeHtml(desc)}</span>` : ''}</td>`;
        html += `<td class="claim-value">${resolved}</td>`;
        html += '</tr>';
    }
    html += '</tbody></table>';
    html += '</div>';
    return html;
}

function buildOidcDiscoverySummary(body) {
    // Shorten URLs by stripping host and replacing tenant GUID with [Tenant ID]
    const shorten = (url) => {
        if (!url || typeof url !== 'string') return String(url);
        const m = url.match(/\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/);
        if (!m) return url;
        const idx = url.indexOf('/' + m[1]);
        return url.slice(idx).replace(m[1], '[Tenant ID]');
    };
    const keys = [
        'authorization_endpoint', 'token_endpoint', 'issuer',
        'jwks_uri', 'userinfo_endpoint',
        'response_types_supported', 'scopes_supported',
    ];
    let html = '<table class="claims-table"><tbody>';
    for (const key of keys) {
        if (body[key] === undefined || body[key] === null) continue;
        const desc = OIDC_PROPERTY_DESCRIPTIONS[key] || '';
        const val = Array.isArray(body[key]) ? body[key].join(', ') : shorten(body[key]);
        html += '<tr>';
        html += `<td class="claim-name">${escapeHtml(key)}${desc ? `<span class="claim-tip">${escapeHtml(desc)}</span>` : ''}</td>`;
        html += `<td class="claim-value">${escapeHtml(val)}</td>`;
        html += '</tr>';
    }
    html += '</tbody></table>';
    return html;
}

function resolveClaimValue(key, value) {
    const strVal = String(value);
    // scp is a space-separated list of scope names, not GUIDs
    if (key === 'scp') return escapeHtml(strVal);
    // Timestamp claims — show human-readable UTC alongside epoch
    if ((key === 'exp' || key === 'iat' || key === 'nbf') && typeof value === 'number') {
        const utc = new Date(value * 1000).toUTCString();
        return `<span class="claim-resolved" title="Unix epoch: ${value}">${escapeHtml(utc)}</span>`;
    }
    // For known IDs, show human-readable label with actual value in parentheses
    if (highlightMap[strVal]) {
        const label = highlightMap[strVal].label;
        return `<span class="claim-resolved" title="${escapeHtml(strVal)}">${escapeHtml(label)} (${escapeHtml(strVal)})</span>`;
    }
    // tid: show the GUID as-is if no friendly name
    return escapeHtml(strVal);
}


// ══════════════════════════════════════════════════════════════════════════
// ── CLAIM/PARAM TOOLTIPS (fixed position to escape overflow clipping) ──
// ══════════════════════════════════════════════════════════════════════════

document.addEventListener('mouseenter', (e) => {
    if (typeof e.target?.closest !== 'function') return;
    const cell = e.target.closest('.claim-name');
    if (!cell) return;
    const tip = cell.querySelector('.claim-tip');
    if (!tip) return;
    const rect = cell.getBoundingClientRect();
    tip.style.left = `${rect.left}px`;
    tip.style.top = `${rect.bottom + 4}px`;
    tip.style.display = 'block';
}, true);

document.addEventListener('mouseleave', (e) => {
    if (typeof e.target?.closest !== 'function') return;
    const cell = e.target.closest('.claim-name');
    if (!cell) return;
    const tip = cell.querySelector('.claim-tip');
    if (tip) tip.style.display = 'none';
}, true);


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


// ══════════════════════════════════════════════════════════════════════════
// ── SIGN-IN LOG: INSTANT PREVIEW EXTRACTION ──
// ══════════════════════════════════════════════════════════════════════════

/**
 * Extract instant sign-in preview data from flow step responses.
 * Each step that has an Entra token response contains correlation IDs,
 * status, timestamps, and decoded JWT claims — available immediately
 * without waiting for Graph auditLogs/signIns (which takes 2-15 min).
 */
function extractSigninPreviews(steps) {
    const previews = [];
    for (const step of steps) {
        const resp = step.response;
        if (!resp) continue;

        const headers = resp.headers || {};
        const body = resp.body || {};
        const tokens = step.tokens || {};

        // Only process Entra token responses (have x-ms-request-id or token fields)
        const correlationId = headers['x-ms-request-id'] || '';
        if (!correlationId && !body.access_token) continue;

        const status = resp.status || 0;
        const isSuccess = status >= 200 && status < 300;
        const timestamp = headers['date'] || new Date().toISOString();
        const estsServer = headers['x-ms-ests-server'] || '';

        // Extract user/app/resource info from decoded JWT claims
        const at = tokens.access_token || {};
        const atPayload = at.payload || {};
        const it = tokens.id_token || {};
        const itPayload = it.payload || {};

        // User info (prefer ID token, fall back to access token)
        const userName = itPayload.name || atPayload.name || '';
        const upn = itPayload.preferred_username || itPayload.upn
            || atPayload.preferred_username || atPayload.upn || '';
        const userId = itPayload.oid || atPayload.oid || '';

        // App info
        const appId = atPayload.azp || atPayload.appid || body.client_id || '';

        // Resource / audience
        const audience = atPayload.aud || '';

        // Scopes / roles
        const scopes = atPayload.scp || '';
        const roles = atPayload.roles || [];

        // Token type (delegated vs app-only)
        const idtyp = atPayload.idtyp || '';
        const isAppOnly = idtyp === 'app' || (roles.length > 0 && !scopes);

        // Auth methods
        const amr = itPayload.amr || atPayload.amr || [];

        // Tenant
        const tenantId = atPayload.tid || itPayload.tid || '';

        // Token lifetime
        const issuedAt = atPayload.iat ? new Date(atPayload.iat * 1000).toISOString() : '';
        const expiresAt = atPayload.exp ? new Date(atPayload.exp * 1000).toISOString() : '';

        // Error info (for failed requests)
        const errorCode = body.error || '';
        const errorDesc = body.error_description || '';

        previews.push({
            _preview: true,
            _stepLabel: step.label || '',
            correlationId,
            createdDateTime: timestamp,
            isSuccess,
            httpStatus: status,
            estsServer,
            // User
            userDisplayName: userName,
            userPrincipalName: upn,
            userId,
            // App
            appId,
            appDisplayName: '',  // not available instantly — Graph fills this
            // Resource
            resourceId: audience,
            resourceDisplayName: '',  // Graph fills this
            // Auth detail
            scopes,
            roles,
            isAppOnly,
            amr,
            tenantId,
            issuedAt,
            expiresAt,
            // Error
            errorCode,
            errorDescription: errorDesc,
            // Fields only available from Graph (will be empty in preview)
            ipAddress: '',
            location: {},
            deviceDetail: {},
            clientAppUsed: '',
            conditionalAccessStatus: '',
            appliedConditionalAccessPolicies: [],
            riskState: '',
            riskDetail: '',
            riskLevelAggregated: '',
            riskLevelDuringSignIn: '',
            isInteractive: null,
        });
    }
    return previews;
}

/**
 * Merge Graph sign-in log entries with instant previews.
 * Match on correlationId. Graph entries replace previews but inherit
 * any extra preview-only fields.
 */
function mergeSigninData(graphEntries, previews) {
    const merged = [];
    const graphByCorrelation = new Map();
    for (const e of graphEntries) {
        if (e.correlationId) {
            graphByCorrelation.set(e.correlationId, e);
        }
    }

    // First add all previews, merging with Graph data where available
    const usedCorrelations = new Set();
    for (const p of previews) {
        const graphEntry = p.correlationId ? graphByCorrelation.get(p.correlationId) : null;
        if (graphEntry) {
            // Merge: Graph entry is canonical, but carry forward preview-only fields
            merged.push({
                ...graphEntry,
                _preview: false,
                _enriched: true,
                _stepLabel: p._stepLabel,
                httpStatus: p.httpStatus,
                estsServer: p.estsServer,
                scopes: p.scopes,
                roles: p.roles,
                isAppOnly: p.isAppOnly,
                amr: p.amr,
                tenantId: p.tenantId || graphEntry.tenantId || '',
                issuedAt: p.issuedAt,
                expiresAt: p.expiresAt,
            });
            usedCorrelations.add(p.correlationId);
        } else {
            merged.push(p);
        }
    }

    // Then add any Graph entries that didn't match a preview
    for (const e of graphEntries) {
        if (e.correlationId && !usedCorrelations.has(e.correlationId)) {
            merged.push({ ...e, _preview: false, _enriched: false });
        }
    }

    return merged;
}


// ══════════════════════════════════════════════════════════════════════════
// ── SIGN-IN LOG POLLING ──
// ══════════════════════════════════════════════════════════════════════════

function startSigninLogPolling(afterTs) {
    stopSigninLogPolling();
    signinLogAfter = afterTs;
    signinLogEntries = [];
    signinLogElapsed = 0;
    signinLogCountdown = 120;  // first check after 2 minutes
    signinLogEmpty.style.display = 'none';
    signinLogToolbar.style.display = 'flex';

    // Extract instant previews from current steps
    signinLogPreviews = extractSigninPreviews(currentSteps);

    // Re-render current step's sign-in log tab with preview data
    if (currentSteps.length > 0) {
        const step = currentSteps[currentStepIndex];
        const resp = step?.response;
        const corrId = (resp && resp.headers) ? (resp.headers['x-ms-request-id'] || '') : '';
        renderSigninLogForStep(corrId);
    }

    updateSigninLogCountdown();

    signinLogTimer = setInterval(() => {
        signinLogCountdown--;
        signinLogElapsed++;
        if (signinLogCountdown <= 0) {
            fetchSigninLogs();
            if (signinLogElapsed >= signinLogMaxTime) {
                stopSigninLogPolling();
                signinLogCountdownEl.textContent = 'Auto-polling stopped.';
                return;
            }
            signinLogCountdown = 30;  // subsequent polls every 30s
        }
        updateSigninLogCountdown();
    }, 1000);
}

function stopSigninLogPolling() {
    if (signinLogTimer) {
        clearInterval(signinLogTimer);
        signinLogTimer = null;
    }
}

function updateSigninLogCountdown() {
    if (!signinLogTimer) return;
    const min = Math.floor(signinLogCountdown / 60);
    const sec = signinLogCountdown % 60;
    const timeStr = `${min}:${sec.toString().padStart(2, '0')}`;
    let prefix;
    if (signinLogEntries.length > 0) {
        prefix = `${signinLogEntries.length} Graph log${signinLogEntries.length === 1 ? '' : 's'} found · Refreshing`;
    } else if (signinLogPreviews.length > 0) {
        prefix = 'Waiting for Graph data';
    } else {
        prefix = 'Logs take 2–5 min';
    }
    signinLogCountdownEl.textContent = `${prefix} · Next check in ${timeStr}`;
}

async function fetchSigninLogs() {
    try {
        btnSigninLogFetch.disabled = true;
        btnSigninLogFetch.textContent = 'Checking...';
        const resp = await fetch(`/api/signin-logs?after=${encodeURIComponent(signinLogAfter)}`);
        const data = await resp.json();

        if (data.error) {
            signinLogContent.innerHTML = `<div class="signin-log-error">${escapeHtml(data.error)}</div>`;
            signinLogEmpty.style.display = 'none';
            return;
        }

        if (data.entries && data.entries.length > 0) {
            // Check for permission errors returned inline
            if (data.entries[0]._error) {
                signinLogContent.innerHTML = `<div class="signin-log-error">${escapeHtml(data.entries[0]._error)}</div>`;
                signinLogEmpty.style.display = 'none';
                stopSigninLogPolling();
                signinLogCountdownEl.textContent = '';
                return;
            }
            signinLogEntries = data.entries;
            // Re-render current step's sign-in log with enriched data
            if (currentSteps.length > 0) {
                const step = currentSteps[currentStepIndex];
                const stepResp = step?.response;
                const corrId = (stepResp && stepResp.headers) ? (stepResp.headers['x-ms-request-id'] || '') : '';
                const hasData = renderSigninLogForStep(corrId);
                // Update tab dim state
                if (tabSigninLogBtn) tabSigninLogBtn.classList.toggle('tab-no-data', !hasData);
            }
        } else if (signinLogEntries.length === 0 && signinLogPreviews.length === 0) {
            signinLogContent.innerHTML = '';
            signinLogEmpty.style.display = 'block';
        }
    } catch (err) {
        signinLogContent.innerHTML = `<div class="signin-log-error">Error: ${escapeHtml(err.message)}</div>`;
    } finally {
        btnSigninLogFetch.disabled = false;
        btnSigninLogFetch.textContent = 'Check Now';
    }
}

/**
 * Render sign-in log entries for a specific step (matched by correlation ID).
 * Returns true if there's data to show (preview or Graph), false otherwise.
 */
function renderSigninLogForStep(correlationId) {
    if (!correlationId) {
        signinLogContent.innerHTML = '';
        signinLogToolbar.style.display = 'none';
        signinLogEmpty.style.display = 'block';
        signinLogEmpty.innerHTML = 'No sign-in log for this step.<br><small>Only token endpoint requests generate Entra sign-in events.</small>';
        return false;
    }

    // Show toolbar for steps that have a correlation ID (token endpoint requests)
    signinLogToolbar.style.display = 'flex';

    // Find matching entries from previews and Graph data
    const allEntries = mergeSigninData(signinLogEntries, signinLogPreviews);
    const stepEntries = allEntries.filter(e => e.correlationId === correlationId);

    if (stepEntries.length === 0) {
        // We have a correlation ID but no entries yet — show placeholder
        signinLogContent.innerHTML = '';
        signinLogEmpty.style.display = 'block';
        signinLogEmpty.innerHTML = `Waiting for sign-in log…<br><small>Correlation: <code>${escapeHtml(correlationId)}</code></small>`;
        return false;
    }

    signinLogEmpty.style.display = 'none';
    renderSigninLogEntries(stepEntries);
    return true;
}

function renderSigninLogs() {
    // Merge Graph entries with instant previews
    const entries = mergeSigninData(signinLogEntries, signinLogPreviews);
    if (entries.length === 0) return;
    renderSigninLogEntries(entries);
}

function renderSigninLogEntries(entries) {
    let html = '';
    for (const entry of entries) {
        const isPreview = !!entry._preview;
        const isEnriched = !!entry._enriched;

        // ── Status ──
        let isSuccess, statusIcon, statusClass;
        if (isPreview) {
            isSuccess = entry.isSuccess;
            statusIcon = isSuccess ? '✓' : '✗';
            statusClass = isSuccess ? 'success' : 'failure';
        } else {
            const status = entry.status || {};
            isSuccess = status.errorCode === 0;
            statusIcon = isSuccess ? '✓' : '✗';
            statusClass = isSuccess ? 'success' : 'failure';
        }

        // ── Timestamp ──
        const ts = entry.createdDateTime || '';
        const displayTime = ts ? new Date(ts).toLocaleString() : 'Unknown';

        // ── Event type ──
        let typeLabel;
        if (isPreview && !isEnriched) {
            typeLabel = entry.isAppOnly ? 'App-only' : 'Delegated';
        } else {
            const eventTypes = entry.signInEventTypes || [];
            typeLabel = entry.isInteractive ? 'Interactive'
                : eventTypes.includes('servicePrincipal') ? 'Service Principal'
                : 'Non-interactive';
        }

        // ── Source badge ──
        let sourceBadge;
        if (isPreview) {
            sourceBadge = '';
        } else if (isEnriched) {
            sourceBadge = '<span class="signin-log-source enriched">Enriched</span>';
        } else {
            sourceBadge = '<span class="signin-log-source graph">Graph</span>';
        }

        // ── Step label ──
        const stepLabel = entry._stepLabel || '';

        html += `<div class="signin-log-entry${isPreview ? ' preview' : ''}">`;
        html += `<div class="signin-log-header">`;
        html += `<span class="signin-log-status ${statusClass}">${statusIcon}</span>`;
        html += `<span class="signin-log-time">${escapeHtml(displayTime)}</span>`;
        html += `<span class="signin-log-type">${escapeHtml(typeLabel)}</span>`;
        html += sourceBadge;
        if (stepLabel) html += `<span class="signin-log-step-label">${escapeHtml(stepLabel)}</span>`;
        html += `</div>`;

        html += `<div class="signin-log-fields">`;

        // ── Status detail ──
        if (isPreview && !isEnriched) {
            if (isSuccess) {
                html += `<div><span class="field-label">Status</span> <span class="field-success">HTTP ${entry.httpStatus}</span></div>`;
            } else {
                html += `<div><span class="field-label">Status</span> <span class="field-error">HTTP ${entry.httpStatus}: ${escapeHtml(entry.errorCode)}</span></div>`;
                if (entry.errorDescription) html += `<div><span class="field-label"></span> <span class="field-dim">${escapeHtml(entry.errorDescription)}</span></div>`;
            }
        } else {
            const status = entry.status || {};
            const failReason = status.failureReason || '';
            const statusExtra = status.additionalDetails || '';
            html += `<div><span class="field-label">Status</span> ${isSuccess ? '<span class="field-success">Success</span>' : `<span class="field-error">${status.errorCode}: ${escapeHtml(failReason)}</span>`}</div>`;
            if (statusExtra) html += `<div><span class="field-label"></span> <span class="field-dim">${escapeHtml(statusExtra)}</span></div>`;
            // Also show HTTP status if enriched
            if (isEnriched && entry.httpStatus) {
                html += `<div><span class="field-label">HTTP</span> ${entry.httpStatus}</div>`;
            }
        }

        // ── User ──
        const user = entry.userDisplayName || entry.userPrincipalName || '';
        const upn = entry.userPrincipalName || '';
        const userId = entry.userId || '';
        if (user) html += `<div><span class="field-label">User</span> ${escapeHtml(user)}${upn && upn !== user ? ' <span class="field-dim">(' + escapeHtml(upn) + ')</span>' : ''}</div>`;
        if (userId) html += `<div><span class="field-label">User OID</span> <span class="field-mono">${escapeHtml(userId)}</span></div>`;

        // ── App ──
        const app = entry.appDisplayName || '';
        const appId = entry.appId || '';
        if (app || appId) html += `<div><span class="field-label">App</span> ${app ? escapeHtml(app) : '<span class="field-dim">—</span>'}${appId ? ' <span class="field-dim">(' + escapeHtml(appId) + ')</span>' : ''}</div>`;

        // ── Resource / Audience ──
        const resource = entry.resourceDisplayName || '';
        const resourceId = entry.resourceId || '';
        if (resource || resourceId) html += `<div><span class="field-label">Resource</span> ${resource ? escapeHtml(resource) : '<span class="field-dim">—</span>'}${resourceId ? ' <span class="field-dim">(' + escapeHtml(resourceId) + ')</span>' : ''}</div>`;

        // ── Scopes / Roles (from JWT — instant or enriched) ──
        const scopes = entry.scopes || '';
        const roles = entry.roles || [];
        if (scopes) html += `<div><span class="field-label">Scopes</span> <span class="field-mono">${escapeHtml(scopes)}</span></div>`;
        if (roles.length > 0) html += `<div><span class="field-label">Roles</span> <span class="field-mono">${escapeHtml(roles.join(', '))}</span></div>`;

        // ── Auth Methods (from JWT) ──
        const amr = entry.amr || [];
        if (amr.length > 0) html += `<div><span class="field-label">Auth Methods</span> <span class="field-mono">${escapeHtml(amr.join(', '))}</span></div>`;

        // ── Client App (from Graph) ──
        const clientApp = entry.clientAppUsed || '';
        if (clientApp) html += `<div><span class="field-label">Client App</span> ${escapeHtml(clientApp)}</div>`;

        // ── IP Address (from Graph) ──
        const ip = entry.ipAddress || '';
        if (ip) html += `<div><span class="field-label">IP Address</span> ${escapeHtml(ip)}</div>`;

        // ── Location (from Graph) ──
        const loc = entry.location || {};
        const locStr = [loc.city, loc.state, loc.countryOrRegion].filter(Boolean).join(', ');
        const geo = loc.geoCoordinates || {};
        if (locStr) html += `<div><span class="field-label">Location</span> ${escapeHtml(locStr)}${geo.latitude ? ' <span class="field-dim">(' + geo.latitude.toFixed(3) + ', ' + geo.longitude.toFixed(3) + ')</span>' : ''}</div>`;

        // ── Device (from Graph) ──
        const device = entry.deviceDetail || {};
        if (device.browser || device.operatingSystem) {
            html += `<div><span class="field-label">Device</span> ${escapeHtml(device.operatingSystem || '?')} · ${escapeHtml(device.browser || '?')}</div>`;
            const deviceFlags = [];
            if (device.isCompliant) deviceFlags.push('Compliant');
            if (device.isManaged) deviceFlags.push('Managed');
            if (device.trustType) deviceFlags.push(device.trustType);
            if (deviceFlags.length > 0) html += `<div><span class="field-label">Device State</span> ${escapeHtml(deviceFlags.join(' · '))}</div>`;
        }

        // ── Conditional Access (from Graph) ──
        const caStatus = entry.conditionalAccessStatus || '';
        const caPolicies = entry.appliedConditionalAccessPolicies || [];
        if (caStatus) {
            html += `<div><span class="field-label">CA Status</span> ${escapeHtml(caStatus)}</div>`;
        } else if (!isPreview) {
            html += `<div><span class="field-label">CA Status</span> <span class="field-dim">N/A</span></div>`;
        }
        if (caPolicies.length > 0) {
            for (const p of caPolicies) {
                const pName = p.displayName || p.id || 'Unknown';
                const pResult = p.result || 'unknown';
                html += `<div><span class="field-label">CA Policy</span> ${escapeHtml(pName)} <span class="field-dim">(${escapeHtml(pResult)})</span></div>`;
            }
        }

        // ── Risk (from Graph) ──
        const riskState = entry.riskState || '';
        const riskDetail = entry.riskDetail || '';
        const riskLevel = entry.riskLevelAggregated || '';
        const riskDuring = entry.riskLevelDuringSignIn || '';
        const hasRisk = (riskState && riskState !== 'none') || (riskLevel && riskLevel !== 'none') || (riskDuring && riskDuring !== 'none');
        if (hasRisk) {
            html += `<div><span class="field-label">Risk State</span> ${escapeHtml(riskState)}</div>`;
            if (riskDetail && riskDetail !== 'none') html += `<div><span class="field-label">Risk Detail</span> ${escapeHtml(riskDetail)}</div>`;
            if (riskLevel && riskLevel !== 'none') html += `<div><span class="field-label">Risk Level</span> ${escapeHtml(riskLevel)}</div>`;
            if (riskDuring && riskDuring !== 'none') html += `<div><span class="field-label">Risk (Sign-in)</span> ${escapeHtml(riskDuring)}</div>`;
        }

        // ── Token Lifetime (from JWT — instant) ──
        const issuedAt = entry.issuedAt || '';
        const expiresAt = entry.expiresAt || '';
        if (issuedAt) html += `<div><span class="field-label">Issued At</span> ${new Date(issuedAt).toLocaleString()}</div>`;
        if (expiresAt) html += `<div><span class="field-label">Expires At</span> ${new Date(expiresAt).toLocaleString()}</div>`;

        // ── Tenant ──
        const tenantId = entry.tenantId || '';
        if (tenantId) html += `<div><span class="field-label">Tenant</span> <span class="field-mono">${escapeHtml(tenantId)}</span></div>`;

        // ── ESTS Server (from instant response headers) ──
        const estsServer = entry.estsServer || '';
        if (estsServer) html += `<div><span class="field-label">ESTS Server</span> <span class="field-dim">${escapeHtml(estsServer)}</span></div>`;

        // ── Correlation ID ──
        const corrId = entry.correlationId || '';
        if (corrId) html += `<div><span class="field-label">Correlation</span> <span class="field-mono">${escapeHtml(corrId)}</span></div>`;

        // ── Log Entry ID (Graph only) ──
        const entryId = entry.id || '';
        if (entryId) html += `<div><span class="field-label">Log Entry ID</span> <span class="field-mono">${escapeHtml(entryId)}</span></div>`;

        // ── Pending Graph fields indicator for preview-only entries ──
        if (isPreview) {
            html += `<div class="signin-log-pending"><span class="field-dim">⏳ Waiting for Graph sign-in log (CA policies, device, risk, location, IP)…</span></div>`;
        }

        html += `</div></div>`;
    }
    signinLogContent.innerHTML = html;
}

// Manual fetch button
btnSigninLogFetch.addEventListener('click', () => {
    fetchSigninLogs();
    signinLogCountdown = 30;
    updateSigninLogCountdown();
});


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
            // Show context banner (e.g. Session Bootstrap explanation)
            if (result.context && stepContextBanner) {
                stepContextBanner.textContent = result.context;
                stepContextBanner.style.display = '';
            } else if (stepContextBanner) {
                stepContextBanner.style.display = 'none';
            }
            if (result.steps && result.steps.length > 0) {
                setSteps(result.steps);
            } else {
                displayResultLegacy(result, data.flow_type || 'auth_code');
            }
            if (data.diagram) await renderMermaid(data.diagram);
            // Restore composite controls from the returned flow_type
            if (data.flow_type) {
                currentFlowType = data.flow_type;
                const ft = data.flow_type;
                if (ft === 'client_credentials' || ft === 'client_credentials_chain') {
                    authCategory = 'client_credentials'; clientType = 'app';
                } else if (ft === 'agent_id_autonomous' || ft === 'agent_id_autonomous_chain') {
                    authCategory = 'client_credentials'; clientType = 'agent';
                } else if (ft === 'obo') {
                    authCategory = 'user_auth'; clientType = 'app';
                } else if (ft === 'agent_id_obo') {
                    authCategory = 'user_auth'; clientType = 'agent';
                } else if (ft === 'profile_login') {
                    authCategory = 'user_auth'; clientType = 'app';
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
                if (ft === 'profile_login') {
                    diagramHeader.textContent = 'Session Bootstrap — OpenID Connect Sign-In';
                    diagramHeader.style.display = '';
                } else {
                    updateDiagramHeader();
                }
            }
            if (currentSteps.length > 0) highlightDiagramStep(currentStepIndex);

            // Start sign-in log polling (use saved timestamp or fallback to 5 min ago)
            const savedStart = sessionStorage.getItem('flow_start_time');
            sessionStorage.removeItem('flow_start_time');
            startSigninLogPolling(savedStart || new Date(Date.now() - 5 * 60000).toISOString());
        }
        // Refresh highlights (subjects discovered from auth code redirect tokens)
        await loadHighlights();
        if (currentSteps.length > 0) showStep(currentStepIndex);
        // Refresh profile avatar (new ID token may have arrived)
        loadProfile();
    } catch { /* no prior result */ }
});
