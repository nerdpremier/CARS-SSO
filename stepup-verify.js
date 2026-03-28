(function() {
  const statusBox = document.getElementById('status-box');
  const form = document.getElementById('stepup-form');
  const codeInput = document.getElementById('stepup-code');
  const verifyBtn = document.getElementById('stepup-verify-btn');
  const resendBtn = document.getElementById('resend-btn');
  const cancelLink = document.getElementById('cancel-link');

  let challengeId = null;
  let returnUrl = null;
  let csrfToken = null;
  let resendTimeout = null;

  function initializeParams() {
    const params = new URLSearchParams(window.location.search);
    challengeId = params.get('challenge_id');
    returnUrl = params.get('return_url');

    if (!challengeId || !returnUrl) {
      showError('Invalid or missing parameters. No challenge or return URL provided.');
      form.style.display = 'none';
      resendBtn.style.display = 'none';
      return false;
    }

    if (cancelLink) {
      cancelLink.href = returnUrl;
    }
    return true;
  }

  async function getCsrfToken() {
    try {
      const response = await fetch('/api/csrf', {
        method: 'GET',
        headers: {
          'Accept': 'application/json'
        }
      });
      if (!response.ok) {
        throw new Error('Failed to fetch CSRF token');
      }
      const data = await response.json();
      csrfToken = data.token;
    } catch (error) {
      console.error('CSRF token fetch error:', error);
      showError('Unable to initialize security. Please refresh and try again.');
    }
  }

  function showStatus(message, type) {
    statusBox.textContent = message;
    statusBox.className = 'status-box ' + type;
    statusBox.hidden = false;
  }

  function showError(message) {
    showStatus(message, 'danger');
  }

  function showSuccess(message) {
    showStatus(message, 'success');
  }

  function showLoading(message) {
    showStatus(message, 'loading');
  }

  function clearStatus() {
    statusBox.hidden = true;
    statusBox.textContent = '';
    statusBox.className = 'status-box';
  }

  async function verifyCode(code) {
    if (!csrfToken) {
      showError('Security token missing. Please refresh the page.');
      return;
    }

    showLoading('Verifying code...');
    verifyBtn.disabled = true;
    verifyBtn.classList.add('btn--loading');

    try {
      const response = await fetch('/api/stepup', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': csrfToken
        },
        body: JSON.stringify({
          action: 'redirect-verify',
          challenge_id: challengeId,
          code: code
        })
      });

      const data = await response.json();

      if (!response.ok) {
        if (response.status === 429) {
          showError('Too many attempts. Please try again later.');
        } else if (data.error === 'Code expired') {
          showError('Verification code has expired. Please request a new one.');
          codeInput.value = '';
          codeInput.focus();
        } else if (data.error === 'Wrong code') {
          showError('The code you entered is incorrect. Please try again.');
          codeInput.value = '';
          codeInput.focus();
        } else if (data.error === 'Challenge already verified') {
          showSuccess('Already verified. Redirecting...');
          setTimeout(function() { window.location.href = returnUrl; }, 1000);
          return;
        } else {
          showError(data.error || 'Verification failed. Please try again.');
          codeInput.value = '';
          codeInput.focus();
        }
        return;
      }

      showSuccess('Code verified successfully. Redirecting...');
      var stepupToken = data.stepup_token || data.token;
      var redirectUrl = returnUrl + (returnUrl.includes('?') ? '&' : '?') +
                        'stepup_verified=1&stepup_token=' + encodeURIComponent(stepupToken);

      setTimeout(function() {
        document.body.classList.add('page-exit');
        setTimeout(function() {
          window.location.href = redirectUrl;
        }, 200);
      }, 600);
    } catch (error) {
      console.error('Verification error:', error);
      showError('Network error. Please check your connection and try again.');
    } finally {
      verifyBtn.disabled = false;
      verifyBtn.classList.remove('btn--loading');
    }
  }

  async function resendCode() {
    if (!csrfToken) {
      showError('Security token missing. Please refresh the page.');
      return;
    }

    showLoading('Resending code...');
    resendBtn.disabled = true;

    try {
      var response = await fetch('/api/stepup', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': csrfToken
        },
        body: JSON.stringify({
          action: 'redirect-resend',
          challenge_id: challengeId
        })
      });

      var data = await response.json();

      if (!response.ok) {
        if (response.status === 429) {
          showError('Too many resend attempts. Please try again in a few minutes.');
        } else {
          showError(data.message || 'Failed to resend code. Please try again.');
        }
        return;
      }

      if (data.new_challenge_id) {
        challengeId = data.new_challenge_id;
      }
      showSuccess('New code sent to your email. Check your inbox.');
      codeInput.value = '';
      codeInput.focus();

      resendBtn.disabled = true;
      var countdown = 60;
      resendBtn.textContent = 'Resend Code (' + countdown + 's)';

      resendTimeout = setInterval(function() {
        countdown--;
        if (countdown > 0) {
          resendBtn.textContent = 'Resend Code (' + countdown + 's)';
        } else {
          clearInterval(resendTimeout);
          resendBtn.disabled = false;
          resendBtn.textContent = 'Resend Code';
        }
      }, 1000);
    } catch (error) {
      console.error('Resend error:', error);
      showError('Network error. Please try again.');
    }
  }

  form.addEventListener('submit', function(e) {
    e.preventDefault();
    var code = codeInput.value.trim();

    if (code.length !== 6 || !/^\d{6}$/.test(code)) {
      showError('Please enter a valid 6-digit code.');
      return;
    }

    verifyCode(code);
  });

  resendBtn.addEventListener('click', function(e) {
    e.preventDefault();
    resendCode();
  });

  codeInput.addEventListener('input', function(e) {
    e.target.value = e.target.value.replace(/\D/g, '').slice(0, 6);
  });

  if (initializeParams()) {
    getCsrfToken();
  }
})();
