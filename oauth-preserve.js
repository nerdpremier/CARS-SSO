// OAuth Params Preservation Utility
// This script preserves OAuth parameters across page navigation

(function() {
  const OAUTH_KEYS = ['client_id', 'redirect_uri', 'response_type', 'state', 'scope', 'code_challenge', 'code_challenge_method', 'pre_login_log_id'];
  const STORAGE_KEY = 'oauth_pending_flow';

  function getCurrentOAuthParams() {
    const sp = new URLSearchParams(window.location.search);
    const params = {};
    let hasOAuth = false;
    
    for (const key of OAUTH_KEYS) {
      const value = sp.get(key);
      if (value) {
        params[key] = value;
        hasOAuth = true;
      }
    }
    
    return hasOAuth ? params : null;
  }

  function saveOAuthParams(params) {
    if (params) {
      sessionStorage.setItem(STORAGE_KEY, JSON.stringify(params));
    }
  }

  function getSavedOAuthParams() {
    try {
      const saved = sessionStorage.getItem(STORAGE_KEY);
      return saved ? JSON.parse(saved) : null;
    } catch {
      return null;
    }
  }

  function buildQueryString(params) {
    const sp = new URLSearchParams();
    for (const [key, value] of Object.entries(params)) {
      if (value) sp.set(key, value);
    }
    return sp.toString();
  }

  function appendParamsToUrl(url, params) {
    if (!params) return url;
    
    try {
      const u = new URL(url, window.location.origin);
      // Only append to internal URLs
      if (u.origin !== window.location.origin) return url;
      
      for (const [key, value] of Object.entries(params)) {
        if (!u.searchParams.has(key)) {
          u.searchParams.set(key, value);
        }
      }
      return u.pathname + u.search + u.hash;
    } catch {
      return url;
    }
  }

  function updateInternalLinks() {
    const savedParams = getSavedOAuthParams();
    if (!savedParams) return;

    // Update all internal links
    document.querySelectorAll('a[href]').forEach(link => {
      const href = link.getAttribute('href');
      if (!href || href.startsWith('#') || href.startsWith('javascript:') || 
          href.startsWith('mailto:') || href.startsWith('tel:')) return;
      
      const newHref = appendParamsToUrl(href, savedParams);
      if (newHref !== href) {
        link.setAttribute('href', newHref);
      }
    });

    // Update forms
    document.querySelectorAll('form[action]').forEach(form => {
      const action = form.getAttribute('action');
      if (!action) return;
      
      const newAction = appendParamsToUrl(action, savedParams);
      if (newAction !== action) {
        form.setAttribute('action', newAction);
      }
    });
  }

  // On page load: check for OAuth params and save them
  const currentParams = getCurrentOAuthParams();
  if (currentParams) {
    saveOAuthParams(currentParams);
  }

  // Update links on page load
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', updateInternalLinks);
  } else {
    updateInternalLinks();
  }

  // Also update links dynamically added to the page
  const observer = new MutationObserver((mutations) => {
    let shouldUpdate = false;
    for (const mutation of mutations) {
      for (const node of mutation.addedNodes) {
        if (node.nodeType === 1 && (node.tagName === 'A' || node.tagName === 'FORM' || node.querySelector)) {
          shouldUpdate = true;
          break;
        }
      }
    }
    if (shouldUpdate) {
      updateInternalLinks();
    }
  });

  observer.observe(document.body, { childList: true, subtree: true });

  // Expose utility functions globally
  window.OAuthUtil = {
    getSavedParams: getSavedOAuthParams,
    saveParams: saveOAuthParams,
    clearParams: () => sessionStorage.removeItem(STORAGE_KEY),
    appendToUrl: appendParamsToUrl
  };
})();
