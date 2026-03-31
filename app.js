/* ═══════════════════════════════════════════════════════════
   DepScan — Core Application Logic
   Auth · Data Engine · Search · Settings
   ═══════════════════════════════════════════════════════════ */

const DepScan = (() => {
  'use strict';

  // ── Configuration ─────────────────────────────────────────
  // Replace these with your actual values after setup
  const CONFIG = {
    GITHUB_CLIENT_ID:  'Ov23liI69gmAgv5aZktQ',    // ← from GitHub OAuth App
    OAUTH_PROXY_URL:   'https://depscan-oauth-proxy.depscan.workers.dev', // ← the Cloudflare Worker you just deployed
    REDIRECT_URI:      window.location.href.split('?')[0].replace(/\/?(index\.html)?$/, '') + '/oauth-callback.html',
    SCOPES:            'repo read:org',
    CACHE_TTL_MS:      60 * 60 * 1000,              // 1 hour
    API_BASE:          'https://api.github.com',
    CONCURRENCY:       6,                            // parallel SBOM requests
    SEARCH_DEBOUNCE:   200,                          // ms
  };

  // ── State ─────────────────────────────────────────────────
  let state = {
    token: null,
    user: null,
    repos: [],
    orgs: [],
    enabledOrgs: new Set(),       // org logins to scan
    index: new Map(),             // packageName → [{repo, version, ecosystem, visibility}]
    repoIndex: new Map(),         // repo.full_name → [{name, version, ecosystem}]
    ecosystems: new Set(),
    owners: new Set(),
    scanning: false,
    scanComplete: false,
    expandedRow: null,
  };

  // ══════════════════════════════════════════════════════════
  //  PHASE 1: AUTHENTICATION
  // ══════════════════════════════════════════════════════════

  function init() {
    state.token = sessionStorage.getItem('gh_token');
    if (state.token) {
      onAuthenticated();
    } else {
      showView('view-landing');
    }
  }

  function startOAuth() {
    const oauthState = crypto.randomUUID();
    sessionStorage.setItem('oauth_state', oauthState);
    const params = new URLSearchParams({
      client_id: CONFIG.GITHUB_CLIENT_ID,
      redirect_uri: CONFIG.REDIRECT_URI,
      scope: CONFIG.SCOPES,
      state: oauthState,
    });
    window.location.href = `https://github.com/login/oauth/authorize?${params}`;
  }

  async function onAuthenticated() {
    showView('view-scanning');
    try {
      state.user = await ghGet('/user');
      renderUserAvatar();
      await startScan();
    } catch (err) {
      toast('Authentication failed: ' + err.message, 'error');
      disconnect();
    }
  }

  function renderUserAvatar() {
    const container = document.getElementById('user-avatar-container');
    if (state.user && container) {
      container.innerHTML = `<img class="user-avatar" src="${escHtml(state.user.avatar_url)}" alt="${escHtml(state.user.login)}" title="${escHtml(state.user.login)}">`;
    }
  }

  // ══════════════════════════════════════════════════════════
  //  PHASE 2: DATA ENGINE & SCANNING
  // ══════════════════════════════════════════════════════════

  async function startScan() {
    state.scanning = true;
    state.index.clear();
    state.repoIndex.clear();
    state.ecosystems.clear();
    state.owners.clear();

    updateScanUI('Fetching repositories…', 'Getting your repo list from GitHub');

    try {
      // Fetch repos and orgs in parallel
      const [userRepos, orgs] = await Promise.all([
        fetchAllPages('/user/repos?per_page=100&type=all'),
        ghGet('/user/orgs').catch(() => []),
      ]);

      state.orgs = orgs || [];
      
      // Initialize enabledOrgs to all orgs on the first scan run
      if (state.enabledOrgs.size === 0) {
        for (const org of state.orgs) {
          state.enabledOrgs.add(org.login);
        }
      }

      state.repos = [...userRepos];

      // Fetch org repos (only for currently enabled orgs)
      for (const org of state.orgs) {
        if (!state.enabledOrgs.has(org.login)) continue;
        try {
          const orgRepos = await fetchAllPages(`/orgs/${org.login}/repos?per_page=100`);
          state.repos.push(...orgRepos);
        } catch (err) {
          addFeedItem(`Failed to fetch ${org.login} repos`, 'error');
        }
      }

      // Deduplicate repos by id AND filter out disabled orgs that came from /user/repos
      const seen = new Set();
      state.repos = state.repos.filter(r => {
        if (seen.has(r.id)) return false;

        // Skip organization repositories if that organization is disabled in settings
        if (r.owner.type === 'Organization' && !state.enabledOrgs.has(r.owner.login)) {
           return false;
        }

        seen.add(r.id);
        return true;
      });

      // Collect owners and pre-seed the repoIndex so that expected 'total repos scanned' matches actual repos attempting to scan
      state.repos.forEach(repo => {
        state.owners.add(repo.owner.login);
        
        // Seed an empty entry so 'Repos Scanned' stat counts repos even if their SBOM fetch fails (e.g. 404 Dependency graph disabled)
        state.repoIndex.set(repo.full_name, {
          full_name: repo.full_name,
          visibility: repo.private ? 'private' : 'public',
          owner: repo.owner.login,
          html_url: repo.html_url,
          packages: []
        });
      });

      const total = state.repos.length;
      updateScanUI(`Scanning ${total} repositories…`, 'Fetching dependency data (SBOMs)');
      document.getElementById('scan-count').textContent = `0 / ${total} repos`;

      // Fetch SBOMs concurrently with controlled concurrency
      let completed = 0;
      let totalPkgs = 0;

      const queue = [...state.repos];
      const workers = [];

      for (let i = 0; i < Math.min(CONFIG.CONCURRENCY, queue.length); i++) {
        workers.push((async () => {
          while (queue.length > 0) {
            const repo = queue.shift();
            try {
              const pkgs = await fetchSBOM(repo);
              if (pkgs && pkgs.length > 0) {
                totalPkgs += pkgs.length;
                addFeedItem(`${repo.full_name} — ${pkgs.length} packages`, 'success', pkgs.length);
              } else {
                addFeedItem(`${repo.full_name} — no SBOM`, 'warning');
              }
            } catch (err) {
              if (err.status === 404) {
                addFeedItem(`${repo.full_name} — dependency graph not enabled`, 'warning');
              } else if (err.status === 403) {
                addFeedItem(`Rate limit hit — waiting 60s…`, 'error');
                await sleep(60000);
                queue.unshift(repo); // retry
                continue;
              } else {
                addFeedItem(`${repo.full_name} — ${err.message}`, 'error');
              }
            }

            completed++;
            const pct = Math.round((completed / total) * 100);
            document.getElementById('scan-progress-fill').style.width = pct + '%';
            document.getElementById('scan-count').textContent = `${completed} / ${total} repos`;
            document.getElementById('scan-packages').textContent = `${totalPkgs} packages found`;
          }
        })());
      }

      await Promise.all(workers);

      state.scanning = false;
      state.scanComplete = true;
      showDashboard();

    } catch (err) {
      toast('Scan failed: ' + err.message, 'error');
      state.scanning = false;
    }
  }

  async function fetchSBOM(repo) {
    const cacheKey = `sbom:${repo.full_name}`;
    const etagKey = `etag:${repo.full_name}`;
    const tsKey = `ts:${repo.full_name}`;

    // Check cache
    const cached = localStorage.getItem(cacheKey);
    const cachedTs = localStorage.getItem(tsKey);
    const cachedEtag = localStorage.getItem(etagKey);

    if (cached && cachedTs && Date.now() - parseInt(cachedTs) < CONFIG.CACHE_TTL_MS) {
      const pkgs = JSON.parse(cached);
      indexPackages(repo, pkgs);
      return pkgs;
    }

    // Fetch from API
    const headers = { Authorization: `token ${state.token}`, Accept: 'application/json' };
    if (cachedEtag) headers['If-None-Match'] = cachedEtag;

    const response = await fetch(`${CONFIG.API_BASE}/repos/${repo.full_name}/dependency-graph/sbom`, { headers });

    if (response.status === 304 && cached) {
      // Not modified — refresh TTL
      localStorage.setItem(tsKey, Date.now().toString());
      const pkgs = JSON.parse(cached);
      indexPackages(repo, pkgs);
      return pkgs;
    }

    if (!response.ok) {
      const err = new Error(`HTTP ${response.status}`);
      err.status = response.status;
      throw err;
    }

    const data = await response.json();
    const etag = response.headers.get('etag');

    // Parse SPDX SBOM
    const packages = (data.sbom?.packages || [])
      .filter(p => p.SPDXID !== 'SPDXRef-DOCUMENT' && p.name)
      .map(p => {
        const { name, ecosystem } = parsePackageInfo(p);
        return {
          name,
          version: p.versionInfo || 'unknown',
          ecosystem,
        };
      });

    // Cache
    try {
      localStorage.setItem(cacheKey, JSON.stringify(packages));
      localStorage.setItem(tsKey, Date.now().toString());
      if (etag) localStorage.setItem(etagKey, etag);
    } catch (e) {
      // localStorage full — continue without caching
    }

    indexPackages(repo, packages);
    return packages;
  }

  function parsePackageInfo(pkg) {
    let ecosystem = null;
    let name = pkg.name || 'unknown';

    // Try to extract ecosystem from PURL in externalRefs (e.g., pkg:pypi/requests)
    if (pkg.externalRefs) {
      const purlRef = pkg.externalRefs.find(r => r.referenceType === 'purl');
      if (purlRef && purlRef.referenceLocator) {
        const match = purlRef.referenceLocator.match(/^pkg:([^\/]+)\//);
        if (match) {
          ecosystem = match[1].toLowerCase();
        }
      }
    }

    // SPDX legacy format check or name cleanup: "npm:axios" or "pip:requests"
    const colonIdx = name.indexOf(':');
    if (colonIdx > 0) {
      if (!ecosystem) {
        ecosystem = name.substring(0, colonIdx).toLowerCase();
      }
      name = name.substring(colonIdx + 1);
    }
    
    return { 
      ecosystem: ecosystem || 'other', 
      name 
    };
  }

  function indexPackages(repo, packages) {
    const repoInfo = {
      full_name: repo.full_name,
      visibility: repo.private ? 'private' : 'public',
      owner: repo.owner.login,
      html_url: repo.html_url,
    };

    const repoPackages = [];

    for (const pkg of packages) {
      state.ecosystems.add(pkg.ecosystem);

      // Global index: packageName → [entries]
      if (!state.index.has(pkg.name)) {
        state.index.set(pkg.name, []);
      }
      state.index.get(pkg.name).push({
        repo: repo.full_name,
        version: pkg.version,
        ecosystem: pkg.ecosystem,
        visibility: repoInfo.visibility,
        owner: repoInfo.owner,
        html_url: repoInfo.html_url,
      });

      repoPackages.push(pkg);
    }

    // Repo index: repo.full_name → [packages]
    state.repoIndex.set(repo.full_name, {
      ...repoInfo,
      packages: repoPackages,
    });
  }

  // ── API Helpers ───────────────────────────────────────────

  async function ghGet(path) {
    const res = await fetch(`${CONFIG.API_BASE}${path}`, {
      headers: {
        Authorization: `token ${state.token}`,
        Accept: 'application/vnd.github+json',
      },
    });
    if (!res.ok) {
      const err = new Error(`GitHub API ${res.status}`);
      err.status = res.status;
      throw err;
    }
    return res.json();
  }

  async function fetchAllPages(path) {
    let results = [];
    let url = `${CONFIG.API_BASE}${path}`;

    while (url) {
      const res = await fetch(url, {
        headers: {
          Authorization: `token ${state.token}`,
          Accept: 'application/vnd.github+json',
        },
      });
      if (!res.ok) {
        const err = new Error(`GitHub API ${res.status}`);
        err.status = res.status;
        throw err;
      }
      const data = await res.json();
      results = results.concat(data);

      // Parse Link header for next page
      const link = res.headers.get('link');
      url = null;
      if (link) {
        const match = link.match(/<([^>]+)>;\s*rel="next"/);
        if (match) url = match[1];
      }
    }
    return results;
  }

  // ── Scan UI Helpers ───────────────────────────────────────

  function updateScanUI(title, subtitle) {
    document.getElementById('scan-title').textContent = title;
    document.getElementById('scan-subtitle').textContent = subtitle;
  }

  function addFeedItem(text, type = '', count = null) {
    const feed = document.getElementById('scan-feed');
    const item = document.createElement('div');
    item.className = `scan-feed-item ${type}`;
    item.innerHTML = `
      <span class="feed-dot"></span>
      <span class="feed-repo">${escHtml(text)}</span>
      ${count !== null ? `<span class="feed-count">${count} pkgs</span>` : ''}
    `;
    feed.insertBefore(item, feed.firstChild);

    // Keep feed manageable
    while (feed.children.length > 100) {
      feed.removeChild(feed.lastChild);
    }
  }

  // ══════════════════════════════════════════════════════════
  //  PHASE 3: SEARCH & DASHBOARD UI
  // ══════════════════════════════════════════════════════════

  function showDashboard() {
    showView('view-dashboard');
    populateFilters();
    updateStats();
    renderResults();
    setupSearch();
  }

  function setupSearch() {
    const searchInput = document.getElementById('search-input');
    let debounceTimer;

    searchInput.addEventListener('input', () => {
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(() => renderResults(), CONFIG.SEARCH_DEBOUNCE);
    });

    // Filters
    ['filter-ecosystem', 'filter-visibility', 'filter-owner', 'filter-sort'].forEach(id => {
      document.getElementById(id).addEventListener('change', () => renderResults());
    });

    searchInput.focus();
  }

  function populateFilters() {
    // Ecosystems
    const ecoSelect = document.getElementById('filter-ecosystem');
    ecoSelect.innerHTML = '<option value="">All Ecosystems</option>';
    [...state.ecosystems].sort().forEach(eco => {
      const opt = document.createElement('option');
      opt.value = eco;
      opt.textContent = eco;
      ecoSelect.appendChild(opt);
    });

    // Owners
    const ownerSelect = document.getElementById('filter-owner');
    ownerSelect.innerHTML = '<option value="">All Owners</option>';
    [...state.owners].sort().forEach(owner => {
      const opt = document.createElement('option');
      opt.value = owner;
      opt.textContent = owner;
      ownerSelect.appendChild(opt);
    });
  }

  function updateStats() {
    document.getElementById('stat-repos').textContent = state.repoIndex.size;

    let totalPkgs = 0;
    state.index.forEach(entries => totalPkgs += entries.length);
    document.getElementById('stat-packages').textContent = state.index.size;
    document.getElementById('stat-ecosystems').textContent = state.ecosystems.size;
  }

  function renderResults() {
    const query = (document.getElementById('search-input').value || '').trim().toLowerCase();
    const filterEco = document.getElementById('filter-ecosystem').value;
    const filterVis = document.getElementById('filter-visibility').value;
    const filterOwner = document.getElementById('filter-owner').value;
    const sortBy = document.getElementById('filter-sort').value;

    const tbody = document.getElementById('results-body');
    const emptyEl = document.getElementById('results-empty');
    const countEl = document.getElementById('search-result-count');
    const tableEl = document.getElementById('results-table');

    // Build filtered list
    let results = [];

    state.index.forEach((entries, pkgName) => {
      // Find out if the package itself matches the query
      const packageMatches = !query || pkgName.toLowerCase().includes(query);

      // Group by version
      const versionGroups = {};
      entries.forEach(e => {
        const v = e.version || 'unknown';
        if (!versionGroups[v]) versionGroups[v] = [];
        versionGroups[v].push(e);
      });

      Object.entries(versionGroups).forEach(([version, verEntries]) => {
        // Filter entries by repository (if package didn't match), ecosystem, visibility, and owner
        let filtered = verEntries;

        if (query && !packageMatches) {
          filtered = filtered.filter(e => e.repo.toLowerCase().includes(query));
        }

        if (filterEco) filtered = filtered.filter(e => e.ecosystem === filterEco);
        if (filterVis) filtered = filtered.filter(e => e.visibility === filterVis);
        if (filterOwner) filtered = filtered.filter(e => e.owner === filterOwner);

        if (filtered.length === 0) return;

        const ecosystems = [...new Set(filtered.map(e => e.ecosystem))];

        results.push({
          name: pkgName,
          version: version,
          entries: filtered,
          ecosystems,
          repoCount: filtered.length,
          rowKey: pkgName + '@' + version
        });
      });
    });

    // Sort
    results.sort((a, b) => {
      switch (sortBy) {
        case 'repos': return b.repoCount - a.repoCount;
        case 'ecosystem': return (a.ecosystems[0] || '').localeCompare(b.ecosystems[0] || '');
        default: {
          const nameCmp = a.name.localeCompare(b.name);
          if (nameCmp !== 0) return nameCmp;
          return a.version.localeCompare(b.version);
        }
      }
    });

    // Render
    tbody.innerHTML = '';
    state.expandedRow = null;

    if (results.length === 0) {
      emptyEl.style.display = 'flex';
      tableEl.style.display = 'none';
      countEl.textContent = '';
      return;
    }

    emptyEl.style.display = 'none';
    tableEl.style.display = 'table';
    countEl.textContent = `${results.length} package${results.length !== 1 ? 's' : ''}`;

    // Only render first 200 — virtual scroll could be added later for huge lists
    const renderLimit = 200;
    results.slice(0, renderLimit).forEach(pkg => {
      const tr = document.createElement('tr');
      tr.dataset.pkg = pkg.rowKey;
      tr.addEventListener('click', () => toggleExpand(pkg));

      tr.innerHTML = `
        <td><span class="pkg-name">${escHtml(pkg.name)}</span></td>
        <td class="td-eco">${pkg.ecosystems.map(e => `<span class="eco-badge" data-eco="${escAttr(e)}">${escHtml(e)}</span>`).join(' ')}</td>
        <td><span class="repo-count">${pkg.repoCount}</span></td>
        <td><span class="version-pill">${escHtml(pkg.version)}</span></td>
      `;
      tbody.appendChild(tr);
    });

    if (results.length > renderLimit) {
      const infoRow = document.createElement('tr');
      infoRow.innerHTML = `<td colspan="5" style="text-align:center; color:var(--text-muted); font-size:0.82rem; padding:20px;">Showing ${renderLimit} of ${results.length} packages. Refine your search to see more.</td>`;
      tbody.appendChild(infoRow);
    }
  }

  function toggleExpand(pkg) {
    const tbody = document.getElementById('results-body');
    const existingExpanded = tbody.querySelector('.expanded-row');

    // Close if same row
    if (existingExpanded && existingExpanded.dataset.pkg === pkg.rowKey) {
      existingExpanded.remove();
      state.expandedRow = null;
      return;
    }

    // Close existing
    if (existingExpanded) existingExpanded.remove();

    // Find the clicked row
    const clickedRow = tbody.querySelector(`tr[data-pkg="${CSS.escape(pkg.rowKey)}"]`);
    if (!clickedRow) return;

    // Create expanded row
    const expRow = document.createElement('tr');
    expRow.className = 'expanded-row';
    expRow.dataset.pkg = pkg.rowKey;
    const td = document.createElement('td');
    td.colSpan = 4;

    td.innerHTML = `
      <div class="expanded-content">
        <table>
          <thead>
            <tr>
              <th>Repository</th>
              <th>Ecosystem</th>
              <th>Version</th>
              <th>Visibility</th>
              <th>Links</th>
            </tr>
          </thead>
          <tbody>
            ${pkg.entries.map(e => `
              <tr>
                <td>
                  <span class="pkg-name" style="cursor:pointer; color:var(--accent-cyan);" onclick="event.stopPropagation(); DepScan.openRepoPanel('${escAttr(e.repo)}')">${escHtml(e.repo)}</span>
                </td>
                <td><span class="eco-badge" data-eco="${escAttr(e.ecosystem)}">${escHtml(e.ecosystem)}</span></td>
                <td><span class="version-pill">${escHtml(e.version)}</span></td>
                <td>${e.visibility === 'private' ? '🔒 Private' : '🌐 Public'}</td>
                <td>
                  <a href="${escAttr(e.html_url)}" class="gh-link-icon" target="_blank" rel="noopener" onclick="event.stopPropagation()">
                    <svg viewBox="0 0 16 16" aria-hidden="true" focusable="false">
                      <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/>
                    </svg>
                  </a>
                </td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    `;

    expRow.appendChild(td);
    clickedRow.after(expRow);
    state.expandedRow = pkg.name;
  }

  // ── Repo Detail Panel ─────────────────────────────────────

  function openRepoPanel(repoFullName) {
    const panel = document.getElementById('repo-panel');
    const repoData = state.repoIndex.get(repoFullName);
    if (!repoData) return;

    document.getElementById('repo-panel-title').textContent = repoFullName;

    // Links
    const linksEl = document.getElementById('repo-panel-links');
    linksEl.innerHTML = `
      <a class="panel-link panel-link-icon" href="${escAttr(repoData.html_url)}" target="_blank" rel="noopener" title="Open repository on GitHub">
        <svg viewBox="0 0 16 16" aria-hidden="true" focusable="false">
          <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/>
        </svg>
      </a>
      <a class="panel-link" href="${escAttr(repoData.html_url)}/network/dependencies" target="_blank" rel="noopener">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="18" cy="18" r="3"/><circle cx="6" cy="6" r="3"/><path d="M13 6h3a2 2 0 0 1 2 2v7"/><path d="M6 9v12"/></svg>
        Dependency Graph
      </a>
      <a class="panel-link" href="${escAttr(repoData.html_url)}/security/dependabot" target="_blank" rel="noopener">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
        Dependabot Alerts
      </a>
    `;

    // Dependencies table
    const depsEl = document.getElementById('repo-panel-deps');
    const pkgs = repoData.packages || [];

    if (pkgs.length === 0) {
      depsEl.innerHTML = '<p class="text-muted" style="padding:24px 0;">No dependencies found for this repository.</p>';
    } else {
      // Group by ecosystem
      const grouped = {};
      pkgs.forEach(p => {
        if (!grouped[p.ecosystem]) grouped[p.ecosystem] = [];
        grouped[p.ecosystem].push(p);
      });

      let html = '';
      Object.entries(grouped).sort((a,b) => a[0].localeCompare(b[0])).forEach(([eco, epkgs]) => {
        html += `<h4 style="margin:16px 0 8px; font-size:0.82rem;"><span class="eco-badge" data-eco="${escAttr(eco)}">${escHtml(eco)}</span> <span class="text-muted" style="margin-left:6px;">${epkgs.length} packages</span></h4>`;
        html += `<table><thead><tr><th>Package</th><th>Version</th></tr></thead><tbody>`;
        epkgs.sort((a,b) => a.name.localeCompare(b.name)).forEach(p => {
          html += `<tr><td><span class="pkg-name">${escHtml(p.name)}</span></td><td><span class="version-pill">${escHtml(p.version)}</span></td></tr>`;
        });
        html += `</tbody></table>`;
      });

      depsEl.innerHTML = html;
    }

    panel.classList.add('open');
    document.body.style.overflow = 'hidden';
  }

  function closeRepoPanel() {
    document.getElementById('repo-panel').classList.remove('open');
    document.body.style.overflow = '';
  }

  // ══════════════════════════════════════════════════════════
  //  PHASE 4: SETTINGS & POLISH
  // ══════════════════════════════════════════════════════════

  function showSettings() {
    const modal = document.getElementById('settings-modal');
    modal.style.display = 'flex';

    // Populate org toggles
    const orgsEl = document.getElementById('settings-orgs');
    if (state.orgs.length === 0) {
      orgsEl.innerHTML = '<p class="text-muted">No organizations found. Personal repos will always be scanned.</p>';
    } else {
      orgsEl.innerHTML = state.orgs.map(org => `
        <div class="org-toggle">
          <input type="checkbox" id="org-${escAttr(org.login)}" ${state.enabledOrgs.has(org.login) ? 'checked' : ''} onchange="DepScan.toggleOrg('${escAttr(org.login)}', this.checked)">
          <label for="org-${escAttr(org.login)}">
            ${escHtml(org.login)}
          </label>
        </div>
      `).join('');
    }

    // Cache info
    let cachedCount = 0;
    for (let i = 0; i < localStorage.length; i++) {
      if (localStorage.key(i).startsWith('sbom:')) cachedCount++;
    }
    document.getElementById('cache-info').textContent = `${cachedCount} repos cached`;

    // Close on backdrop click
    modal.addEventListener('click', (e) => {
      if (e.target === modal) closeSettings();
    });
  }

  function closeSettings() {
    document.getElementById('settings-modal').style.display = 'none';
  }

  function toggleOrg(login, enabled) {
    if (enabled) {
      state.enabledOrgs.add(login);
    } else {
      state.enabledOrgs.delete(login);
    }
  }

  function rescan() {
    // Clear all cached SBOMs
    const keysToRemove = [];
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      if (key.startsWith('sbom:') || key.startsWith('etag:') || key.startsWith('ts:')) {
        keysToRemove.push(key);
      }
    }
    keysToRemove.forEach(k => localStorage.removeItem(k));

    closeSettings();
    showView('view-scanning');

    // Reset scan UI
    document.getElementById('scan-progress-fill').style.width = '0%';
    document.getElementById('scan-count').textContent = '0 / 0 repos';
    document.getElementById('scan-packages').textContent = '0 packages found';
    document.getElementById('scan-feed').innerHTML = '';

    startScan();
  }

  function disconnect() {
    // Clear all stored data
    sessionStorage.removeItem('gh_token');
    sessionStorage.removeItem('oauth_state');

    const keysToRemove = [];
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      if (key.startsWith('sbom:') || key.startsWith('etag:') || key.startsWith('ts:')) {
        keysToRemove.push(key);
      }
    }
    keysToRemove.forEach(k => localStorage.removeItem(k));

    state.token = null;
    state.user = null;
    state.repos = [];
    state.index.clear();
    state.repoIndex.clear();

    closeSettings();
    showView('view-landing');
  }

  function skipToSearch() {
    showDashboard();
  }

  // ── Error / Toast System ──────────────────────────────────

  function toast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;

    let iconSvg = '';
    if (type === 'error') {
      iconSvg = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--accent-red)" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>`;
    } else if (type === 'warn') {
      iconSvg = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--accent-amber)" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`;
    } else if (type === 'success') {
      iconSvg = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--accent-green)" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>`;
    }

    toast.innerHTML = `${iconSvg}<span>${escHtml(message)}</span>`;
    container.appendChild(toast);

    setTimeout(() => {
      toast.classList.add('toast-exit');
      setTimeout(() => toast.remove(), 300);
    }, 5000);
  }

  // ── View Management ───────────────────────────────────────

  function showView(viewId) {
    document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
    const target = document.getElementById(viewId);
    if (target) target.classList.add('active');
  }

  // ── Utilities ─────────────────────────────────────────────

  function escHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.appendChild(document.createTextNode(String(str)));
    return div.innerHTML;
  }

  function escAttr(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');
  }

  function sleep(ms) {
    return new Promise(r => setTimeout(r, ms));
  }

  // ── Public API ────────────────────────────────────────────

  return {
    init,
    startOAuth,
    showSettings,
    closeSettings,
    toggleOrg,
    rescan,
    disconnect,
    openRepoPanel,
    closeRepoPanel,
    skipToSearch,
    toast,
    // Expose CONFIG for oauth-callback to use
    CONFIG,
  };

})();

// ── Boot ─────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', DepScan.init);
