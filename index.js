const config = {
  no_ref: "off", //Control the HTTP referrer header, if you want to create an anonymous link that will hide the HTTP Referer header, please set to "on" .
  theme:"theme/captcha",//Homepage theme, use the empty value for default theme. To use urlcool theme, please fill with "theme/urlcool" . If you need captcha feature, you need to use captcha theme.
  cors: "on",//Allow Cross-origin resource sharing for API requests.
  unique_link:true,//If it is true, the same long url will be shorten into the same short url
  custom_link:false,//Allow users to customize the short url.
  safe_browsing_api_key: "", //Enter Google Safe Browsing API Key to enable url safety check before redirect.
  expiration_ttl: 0, // Short link expiration time in seconds. 86400 = 24 hours. Set to 0 for no expiration.
  
  // CAPTCHA Configuration
  captcha: {
    enabled: true, // Master switch for CAPTCHA service
    api_endpoint: "https://captcha.gurl.eu.org/api", // CAP Worker API endpoint
    require_on_create: true, // Require CAPTCHA when creating short links
    require_on_access: true, // Require CAPTCHA when accessing short links
    timeout: 5000, // API request timeout in milliseconds
    fallback_on_error: true, // Allow operations when CAPTCHA service is down
    max_retries: 2, // Maximum retry attempts for CAPTCHA API calls
  }
  }
  
  const html404 = `<!DOCTYPE html>
  <body>
    <h1>404 Not Found.</h1>
    <p>The url you visit is not found.</p>
    <a href="https://github.com/xyTom/Url-Shorten-Worker/" target="_self">Fork me on GitHub</a>
  </body>`
  
  let response_header={
    "content-type": "text/html;charset=UTF-8",
  } 
  
  if (config.cors=="on"){
    response_header={
    "content-type": "text/html;charset=UTF-8",
    "Access-Control-Allow-Origin":"*",
    "Access-Control-Allow-Methods": "POST",
    }
  }
  
  async function randomString(len) {
  　　len = len || 6;
  　　let $chars = 'ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678';    /****默认去掉了容易混淆的字符oOLl,9gq,Vv,Uu,I1****/
  　　let maxPos = $chars.length;
  　　let result = '';
  　　for (let i = 0; i < len; i++) {
  　　　　result += $chars.charAt(Math.floor(Math.random() * maxPos));
  　　}
  　　return result;
  }
  
  async function sha512(url){
      url = new TextEncoder().encode(url)
  
      const url_digest = await crypto.subtle.digest(
        {
          name: "SHA-512",
        },
        url, // The data you want to hash as an ArrayBuffer
      )
      const hashArray = Array.from(new Uint8Array(url_digest)); // convert buffer to byte array
      const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
      //console.log(hashHex)
      return hashHex
  }
  async function checkURL(URL){
      let str=URL;
      let Expression=/http(s)?:\/\/([\w-]+\.)+[\w-]+(\/[\w- .\/?%&=]*)?/;
      let objExp=new RegExp(Expression);
      if(objExp.test(str)==true){
        if (str[0] == 'h')
          return true;
        else
          return false;
      }else{
          return false;
      }
  } 
  function getKvPutOptions() {
    const MIN_TTL = 60;
    const rawTtl = Number(config.expiration_ttl);
    const hasValidTtl = Number.isFinite(rawTtl) && rawTtl >= MIN_TTL;
    return hasValidTtl ? { expirationTtl: Math.floor(rawTtl) } : {};
  }
  async function save_url(URL){
      let random_key=await randomString()
      let is_exist=await LINKS.get(random_key)
      console.log(is_exist)
      if (is_exist == null) {
          return await LINKS.put(random_key, URL, getKvPutOptions()), random_key
      }
      else
          return save_url(URL)
  }
  async function is_url_exist(url_sha512){
    let is_exist = await LINKS.get(url_sha512)
    console.log(is_exist)
    if (is_exist == null) {
      return false
    }else{
      return is_exist
    }
  }
  async function is_url_safe(url){
  
    let raw = JSON.stringify({"client":{"clientId":"Url-Shorten-Worker","clientVersion":"1.0.7"},"threatInfo":{"threatTypes":["MALWARE","SOCIAL_ENGINEERING","POTENTIALLY_HARMFUL_APPLICATION","UNWANTED_SOFTWARE"],"platformTypes":["ANY_PLATFORM"],"threatEntryTypes":["URL"],"threatEntries":[{"url":url}]}});
  
    let requestOptions = {
      method: 'POST',
      body: raw,
      redirect: 'follow'
    };
  
    let result = await fetch("https://safebrowsing.googleapis.com/v4/threatMatches:find?key="+config.safe_browsing_api_key, requestOptions)
    result = await result.json()
    console.log(result)
    if (Object.keys(result).length === 0){
      return true
    }else{
      return false
    }
  }
  
  // ============ CAPTCHA Service Integration ============
  
  /**
   * Validates CAPTCHA token with retry and fallback mechanism
   * @param {string} token - The CAPTCHA token to validate
   * @param {boolean} keepToken - Whether to keep the token for reuse
   * @returns {Promise<{success: boolean, error?: string, degraded?: boolean}>}
   */
  async function validateCaptchaToken(token, keepToken = false) {
    // If CAPTCHA is disabled, always return success
    if (!config.captcha.enabled) {
      return { success: true, degraded: false };
    }
  
    // Validate token format
    if (!token || typeof token !== 'string' || token.length < 10) {
      return { success: false, error: 'Invalid token format' };
    }
  
    let lastError = null;
    const maxRetries = config.captcha.max_retries || 2;
  
    // Retry mechanism for resilience
    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), config.captcha.timeout);
  
        const response = await fetch(`${config.captcha.api_endpoint}/validate`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'User-Agent': 'Url-Shorten-Worker/1.0.7',
          },
          body: JSON.stringify({ token, keepToken }),
          signal: controller.signal,
        });
  
        clearTimeout(timeoutId);
  
        // Handle various HTTP status codes
        if (response.ok) {
          const result = await response.json();
          return { success: result.success === true, degraded: false };
        }
  
        // Handle specific error codes
        if (response.status === 400 || response.status === 410 || response.status === 404 || response.status === 409) {
          // Client error, no need to retry
          return { success: false, error: 'Invalid or expired token' };
        }
  
        lastError = `HTTP ${response.status}`;
      } catch (error) {
        lastError = error.name === 'AbortError' ? 'Timeout' : error.message;
        console.error(`CAPTCHA validation attempt ${attempt + 1} failed:`, lastError);
  
        // Exponential backoff before retry (except on last attempt)
        if (attempt < maxRetries) {
          await new Promise(resolve => setTimeout(resolve, Math.pow(2, attempt) * 100));
        }
      }
    }
  
    // Service degradation: if fallback is enabled, allow operation
    if (config.captcha.fallback_on_error) {
      console.warn(`CAPTCHA service degraded: ${lastError}. Allowing operation due to fallback policy.`);
      return { success: true, degraded: true };
    }
  
    return { success: false, error: lastError || 'CAPTCHA service unavailable' };
  }
  
  /**
   * Checks if CAPTCHA is required for the current operation
   * @param {string} operation - 'create' or 'access'
   * @returns {boolean}
   */
  function isCaptchaRequired(operation) {
    if (!config.captcha.enabled) {
      return false;
    }
  
    switch (operation) {
      case 'create':
        return config.captcha.require_on_create;
      case 'access':
        return config.captcha.require_on_access;
      default:
        return false;
    }
  }
  
  /**
   * Extracts CAPTCHA token from request
   * @param {Request} request - The incoming request
   * @returns {Promise<string|null>}
   */
  async function extractCaptchaToken(request) {
    const contentType = request.headers.get('content-type') || '';
  
    if (contentType.includes('application/json')) {
      try {
        const body = await request.clone().json();
        return body.captcha_token || body.captchaToken || body.token || null;
      } catch {
        return null;
      }
    }
  
    // Try to extract from URL parameters
    const url = new URL(request.url);
    return url.searchParams.get('captcha_token') || url.searchParams.get('token') || null;
  }
  
  // ============ End CAPTCHA Service Integration ============
  async function handleRequest(request) {
    console.log(request)
    
    // Handle POST request - Create short link
    if (request.method === "POST") {
      let req = await request.json()
      console.log(req["url"])
      
      // Validate URL format
      if (!await checkURL(req["url"])) {
        return new Response(JSON.stringify({
          status: 500,
          error: "Invalid URL format"
        }), {
          headers: response_header,
          status: 400
        })
      }
  
      // CAPTCHA validation for link creation
      if (isCaptchaRequired('create')) {
        const captchaToken = req.captcha_token || req.captchaToken || req.token;
        
        if (!captchaToken) {
          return new Response(JSON.stringify({
            status: 403,
            error: "CAPTCHA token required",
            captcha_required: true
          }), {
            headers: response_header,
            status: 403
          })
        }
  
        const validation = await validateCaptchaToken(captchaToken, false);
        
        if (!validation.success) {
          return new Response(JSON.stringify({
            status: 403,
            error: validation.error || "CAPTCHA verification failed",
            captcha_required: true
          }), {
            headers: response_header,
            status: 403
          })
        }
  
        // Log if service is degraded
        if (validation.degraded) {
          console.warn("Request processed under CAPTCHA service degradation");
        }
      }
  
      // Process short link creation
      let stat, random_key
      if (config.unique_link) {
        let url_sha512 = await sha512(req["url"])
        let url_key = await is_url_exist(url_sha512)
        if (url_key) {
          random_key = url_key
        } else {
          stat, random_key = await save_url(req["url"])
          if (typeof(stat) == "undefined") {
            console.log(await LINKS.put(url_sha512, random_key, getKvPutOptions()))
          }
        }
      } else {
        stat, random_key = await save_url(req["url"])
      }
      
      console.log(stat)
      if (typeof(stat) == "undefined") {
        return new Response(JSON.stringify({
          status: 200,
          key: "/" + random_key,
          short_url: "/" + random_key
        }), {
          headers: response_header,
        })
      } else {
        return new Response(JSON.stringify({
          status: 500,
          error: "Reached KV write limitation"
        }), {
          headers: response_header,
          status: 500
        })
      }
    } else if (request.method === "OPTIONS") {  
      return new Response("", {
        headers: response_header,
      })
    }
  
    // Handle GET request - Access short link
    const requestURL = new URL(request.url)
    const path = requestURL.pathname.split("/")[1]
    const params = requestURL.search
  
    console.log(path)
    
    // Serve homepage (inline Chinese theme)
    if (!path) {
      const html = `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
  <meta name="description" content="快速、安全、可靠的短链接服务">
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://captcha.gurl.eu.org/cap.min.js"></script>
  <title>链接缩短 - 快速安全</title>
  <script>
    tailwind.config = {
      theme: {
        extend: {
          colors: {
            'apple-blue': '#007AFF',
            'apple-blue-dark': '#0051D5',
            'apple-green': '#34C759',
            'apple-red': '#FF3B30',
            'apple-gray': '#86868b',
            'apple-gray-light': '#f5f5f7',
          },
          fontFamily: {
            'sf': ['-apple-system', 'BlinkMacSystemFont', 'SF Pro Display', 'SF Pro Text', 'Helvetica Neue', 'sans-serif'],
          },
          animation: {
            'float': 'float 20s ease-in-out infinite',
            'slide-up': 'slideUp 0.5s cubic-bezier(0.16, 1, 0.3, 1)',
            'fade-in': 'fadeIn 0.3s ease',
            'shake': 'shake 0.5s ease',
            'scale-up': 'scaleUp 0.3s cubic-bezier(0.16, 1, 0.3, 1)',
          },
          keyframes: {
            float: {
              '0%, 100%': { transform: 'translate(0, 0) rotate(0deg)' },
              '33%': { transform: 'translate(30px, -30px) rotate(120deg)' },
              '66%': { transform: 'translate(-20px, 20px) rotate(240deg)' },
            },
            slideUp: {
              'from': { opacity: '0', transform: 'translateY(40px)' },
              'to': { opacity: '1', transform: 'translateY(0)' },
            },
            fadeIn: {
              'from': { opacity: '0', transform: 'translateY(-10px)' },
              'to': { opacity: '1', transform: 'translateY(0)' },
            },
            shake: {
              '0%, 100%': { transform: 'translateX(0)' },
              '25%': { transform: 'translateX(-8px)' },
              '75%': { transform: 'translateX(8px)' },
            },
            scaleUp: {
              'from': { opacity: '0', transform: 'scale(0.9)' },
              'to': { opacity: '1', transform: 'scale(1)' },
            },
          },
        },
      },
    }
  </script>
  <style>
    @media (prefers-color-scheme: dark) {
      :root {
        color-scheme: dark;
      }
    }
    
    .glass {
      backdrop-filter: blur(20px);
      -webkit-backdrop-filter: blur(20px);
    }
    
    .animate-spin-custom {
      animation: spin 0.6s linear infinite;
    }
    
    @keyframes spin {
      to { transform: rotate(360deg); }
    }
    
    /* 移动端输入框和按钮优化 */
    @media (max-width: 640px) {
      #submitBtn {
        min-height: 48px;
      }
      
      #urlInput {
        min-height: 48px;
        font-size: 16px; /* 防止 iOS 自动缩放 */
      }
      
      /* 确保按钮文字不换行 */
      #submitBtn span {
        white-space: nowrap;
      }
      
      /* CAPTCHA widget 缩放 */
      cap-widget {
        transform: scale(0.9);
        transform-origin: center center;
      }
    }
    
    @media (max-width: 420px) {
      cap-widget {
        transform: scale(0.85);
      }
    }
  </style>
</head>
<body class="font-sf bg-apple-gray-light dark:bg-black text-gray-900 dark:text-gray-100 min-h-screen flex items-center justify-center p-5 relative overflow-x-hidden antialiased">
  
  <!-- Animated 返回ground Orbs -->
  <div class="fixed top-[-250px] left-[-250px] w-[500px] h-[500px] rounded-full bg-apple-blue/15 blur-[80px] animate-float pointer-events-none"></div>
  <div class="fixed bottom-[-300px] right-[-300px] w-[600px] h-[600px] rounded-full bg-purple-500/10 blur-[80px] animate-float pointer-events-none" style="animation-delay: -10s;"></div>

  <!-- Main Container -->
  <div class="w-full max-w-2xl relative z-10">
    <!-- Card -->
    <div class="bg-white dark:bg-gray-900 glass rounded-2xl shadow-xl overflow-hidden animate-slide-up">
      
      <!-- Header -->
      <header class="px-6 sm:px-8 py-8 sm:py-10 text-center border-b border-gray-200 dark:border-gray-800">
        <h1 class="text-2xl sm:text-3xl md:text-4xl font-bold tracking-tight mb-2">缩短 your URLs</h1>
        <p class="text-apple-gray dark:text-gray-400 text-xs sm:text-sm md:text-base">快速、安全、可靠的短链接服务</p>
      </header>

      <!-- Body -->
      <div class="p-6 sm:p-8">
        <form id="shortenForm" onsubmit="handle提交(event)">
          <div class="mb-6">
            <label for="urlInput" class="block text-xs font-semibold text-apple-gray dark:text-gray-400 uppercase tracking-wider mb-3">
              输入要缩短的网址
            </label>
            <div class="flex flex-col gap-3">
              <input 
                type="text" 
                id="urlInput" 
                class="w-full h-12 sm:h-12 px-4 text-base bg-apple-gray-light dark:bg-black border-2 border-gray-300 dark:border-gray-700 rounded-lg transition-all duration-200 outline-none focus:border-apple-blue focus:ring-4 focus:ring-apple-blue/10 placeholder-gray-400 dark:placeholder-gray-600"
                placeholder="https://example.com/"
                autocomplete="off"
                spellcheck="false"
                aria-describedby="notice"
              >
              <button 
                type="submit" 
                id="submitBtn"
                class="w-full sm:w-auto sm:min-w-[120px] h-12 px-6 font-semibold text-white bg-apple-blue hover:bg-apple-blue-dark rounded-lg transition-all duration-200 hover:-translate-y-0.5 hover:shadow-lg active:translate-y-0 active:scale-[0.98] disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:translate-y-0 disabled:hover:shadow-none whitespace-nowrap relative overflow-hidden"
              >
                缩短
              </button>
            </div>
          </div>
          <div id="notice" role="alert" aria-live="polite"></div>
        </form>
      </div>

      <!-- Footer -->
      <footer class="px-6 sm:px-8 py-5 sm:py-6 text-center border-t border-gray-200 dark:border-gray-800">
        <a 
          href="https://github.com/xyTom/Url-缩短-Worker/" 
          target="_blank" 
          rel="noopener"
          class="inline-flex items-center gap-2 px-3 py-2 text-xs sm:text-sm font-medium text-apple-blue hover:bg-apple-blue/5 rounded-lg transition-all duration-200 group"
        >
          <span>View Source Code</span>
          <span class="transition-transform duration-200 group-hover:translate-x-1">→</span>
        </a>
      </footer>
    </div>
  </div>

  <!-- CAPTCHA Modal -->
  <div id="captchaModal" class="hidden fixed inset-0 z-50 items-center justify-center p-4 sm:p-5">
    <div class="absolute inset-0 bg-black/50 glass animate-fade-in" onclick="closeModal('captchaModal')"></div>
    <div class="relative w-full max-w-md bg-white dark:bg-gray-900 rounded-2xl shadow-2xl animate-scale-up">
      <div class="flex items-center justify-between px-5 sm:px-6 py-4 sm:py-5 border-b border-gray-200 dark:border-gray-800">
        <h2 class="text-base sm:text-lg font-semibold">CAPTCHA Verification</h2>
        <button 
          type="button" 
          onclick="closeModal('captchaModal')" 
          class="w-8 h-8 flex items-center justify-center text-2xl text-apple-gray hover:bg-apple-gray-light dark:hover:bg-gray-800 rounded-full transition-all duration-200"
          aria-label="关闭"
        >
          ×
        </button>
      </div>
      <div class="p-5 sm:p-6">
        <p class="text-xs sm:text-sm text-apple-gray dark:text-gray-400 text-center mb-5">
          Please complete the CAPTCHA to continue
        </p>
        <div class="flex justify-center">
          <cap-widget 
            id="capWidget" 
            data-cap-api-endpoint="https://captcha.gurl.eu.org/api/">
          </cap-widget>
        </div>
      </div>
    </div>
  </div>

  <!-- Result Modal -->
  <div id="resultModal" class="hidden fixed inset-0 z-50 items-center justify-center p-4 sm:p-5">
    <div class="absolute inset-0 bg-black/50 glass animate-fade-in" onclick="closeModal('resultModal')"></div>
    <div class="relative w-full max-w-md bg-white dark:bg-gray-900 rounded-2xl shadow-2xl animate-scale-up">
      <div class="flex items-center justify-between px-5 sm:px-6 py-4 sm:py-5 border-b border-gray-200 dark:border-gray-800">
        <h2 class="text-base sm:text-lg font-semibold">Short URL Generated</h2>
        <button 
          type="button" 
          onclick="closeModal('resultModal')" 
          class="w-8 h-8 flex items-center justify-center text-2xl text-apple-gray hover:bg-apple-gray-light dark:hover:bg-gray-800 rounded-full transition-all duration-200"
          aria-label="关闭"
        >
          ×
        </button>
      </div>
      <div class="p-5 sm:p-6">
        <div id="resultUrl" class="text-center break-all text-apple-blue font-semibold text-sm sm:text-base"></div>
      </div>
      <div class="flex flex-col gap-3 px-5 sm:px-6 py-4 sm:py-5 border-t border-gray-200 dark:border-gray-800">
        <button 
          type="button" 
          onclick="copyToClipboard()"
          class="w-full h-12 px-6 font-semibold text-white bg-apple-blue hover:bg-apple-blue-dark rounded-lg transition-all duration-200 active:scale-[0.98]"
        >
          复制 Link
        </button>
        <button 
          type="button" 
          onclick="closeModal('resultModal')"
          class="w-full h-12 px-6 font-semibold text-gray-700 dark:text-gray-300 bg-gray-200 dark:bg-gray-800 hover:bg-gray-300 dark:hover:bg-gray-700 rounded-lg transition-all duration-200 active:scale-[0.98]"
        >
          关闭
        </button>
      </div>
    </div>
  </div>

  <script>
    // State Management
    const state = {
      captchaToken: null,
      isProcessing: false,
      pendingUrl: null,
      generatedUrl: null
    };

    // Elements
    const elements = {
      form: document.getElementById('shortenForm'),
      input: document.getElementById('urlInput'),
      submitBtn: document.getElementById('submitBtn'),
      notice: document.getElementById('notice'),
      captchaModal: document.getElementById('captchaModal'),
      resultModal: document.getElementById('resultModal'),
      resultUrl: document.getElementById('resultUrl'),
      capWidget: document.getElementById('capWidget')
    };

    // Initialize
    document.addEventListener('DOMContentLoaded', () => {
      // Setup CAPTCHA listeners
      if (elements.capWidget) {
        // CAPTCHA solved successfully
        elements.capWidget.addEventListener('solve', (e) => {
          state.captchaToken = e.detail.token;
          console.log('✅ CAPTCHA verified');
          closeModal('captchaModal');
          
          if (state.pendingUrl) {
            perform缩短ing(state.pendingUrl);
            state.pendingUrl = null;
          }
        });

        // CAPTCHA error
        elements.capWidget.addEventListener('error', (e) => {
          console.error('❌ CAPTCHA error:', e.detail);
          showNotice('CAPTCHA verification failed. 请重试.', 'error');
        });

        // CAPTCHA reset
        elements.capWidget.addEventListener('reset', () => {
          console.log('🔄 CAPTCHA reset');
          state.captchaToken = null;
        });

        // CAPTCHA progress (optional: for debugging)
        elements.capWidget.addEventListener('progress', (e) => {
          console.log('⏳ CAPTCHA progress:', e.detail);
        });
      }

      // Input validation
      elements.input.addEventListener('input', () => {
        const value = elements.input.value.trim();
        if (value && !isValidUrl(value)) {
          elements.input.classList.add('border-apple-red');
          elements.input.classList.remove('border-gray-300', 'dark:border-gray-700');
        } else {
          elements.input.classList.remove('border-apple-red');
          elements.input.classList.add('border-gray-300', 'dark:border-gray-700');
        }
      });

      // Keyboard shortcuts
      document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
          closeModal('captchaModal');
          closeModal('resultModal');
        }
      });
    });

    // URL Validation
    function isValidUrl(string) {
      try {
        const url = new URL(string);
        return url.protocol === 'http:' || url.protocol === 'https:';
      } catch {
        return false;
      }
    }

    // Form 提交 Handler
    function handle提交(event) {
      event.preventDefault();
      
      if (state.isProcessing) return;

      const url = elements.input.value.trim();

      if (!url) {
        showNotice('Please enter a URL', 'error');
        elements.input.focus();
        return;
      }

      if (!isValidUrl(url)) {
        showNotice('请输入有效的网址 (must include http:// or https://)', 'error');
        elements.input.classList.add('border-apple-red');
        elements.input.focus();
        return;
      }

      elements.input.classList.remove('border-apple-red');
      clearNotice();

      if (!state.captchaToken) {
        state.pendingUrl = url;
        openModal('captchaModal');
        return;
      }

      perform缩短ing(url);
    }

    // Perform URL 缩短ing
    async function perform缩短ing(url) {
      if (state.isProcessing) return;

      state.isProcessing = true;
      setLoading(true);

      try {
        const response = await fetch(window.location.origin, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            url: url,
            captcha_token: state.captchaToken
          })
        });

        const data = await response.json();

        if (data.status === 200) {
          state.generatedUrl = window.location.origin + data.key;
          elements.resultUrl.textContent = state.generatedUrl;
          elements.input.value = '';
          
          // Reset CAPTCHA state after successful generation
          resetCaptcha();
          
          showNotice('Short URL created successfully!', 'success');
          setTimeout(() => {
            openModal('resultModal');
            clearNotice();
          }, 500);
        } else {
          const errorMsg = data.error || 'Unknown error occurred';
          showNotice(errorMsg, 'error');
          
          // Reset CAPTCHA if verification failed
          if (data.captcha_required || errorMsg.toLowerCase().includes('captcha')) {
            resetCaptcha();
          }
        }
      } catch (error) {
        console.error('Request failed:', error);
        showNotice(`网络错误: ${error.message}`, 'error');
        // Reset CAPTCHA on network error
        resetCaptcha();
      } finally {
        state.isProcessing = false;
        setLoading(false);
      }
    }

    // Reset CAPTCHA
    function resetCaptcha() {
      state.captchaToken = null;
      
      // Trigger reset event on widget if available
      if (elements.capWidget && typeof elements.capWidget.reset === 'function') {
        try {
          elements.capWidget.reset();
          console.log('🔄 CAPTCHA widget reset');
        } catch (error) {
          console.warn('Failed to reset CAPTCHA widget:', error);
        }
      }
    }

    // 复制 to Clipboard
    async function copyToClipboard() {
      if (!state.generatedUrl) return;

      const copyBtn = document.querySelector('#resultModal button.bg-apple-blue');
      const originalText = copyBtn.textContent;

      try {
        if (navigator.clipboard) {
          await navigator.clipboard.writeText(state.generatedUrl);
        } else {
          const textarea = document.createElement('textarea');
          textarea.value = state.generatedUrl;
          textarea.style.position = 'fixed';
          textarea.style.opacity = '0';
          document.body.appendChild(textarea);
          textarea.select();
          document.execCommand('copy');
          document.body.removeChild(textarea);
        }

        copyBtn.textContent = '✓ Copied';
        copyBtn.classList.remove('bg-apple-blue', 'hover:bg-apple-blue-dark');
        copyBtn.classList.add('bg-apple-green');

        setTimeout(() => {
          copyBtn.textContent = originalText;
          copyBtn.classList.remove('bg-apple-green');
          copyBtn.classList.add('bg-apple-blue', 'hover:bg-apple-blue-dark');
        }, 2000);
      } catch (error) {
        console.error('复制 failed:', error);
        showNotice('Failed to copy', 'error');
      }
    }

    // Modal Management
    function openModal(modalId) {
      const modal = document.getElementById(modalId);
      if (modal) {
        modal.classList.remove('hidden');
        modal.classList.add('flex');
        document.body.style.overflow = 'hidden';
      }
    }

    function closeModal(modalId) {
      const modal = document.getElementById(modalId);
      if (modal) {
        modal.classList.add('hidden');
        modal.classList.remove('flex');
        document.body.style.overflow = '';
        
        // Reset CAPTCHA when closing the CAPTCHA modal without completing
        if (modalId === 'captchaModal' && !state.captchaToken) {
          state.pendingUrl = null;
          resetCaptcha();
        }
      }
    }

    // Notice Management
    function showNotice(message, type = 'error') {
      const bgColor = type === 'success' 
        ? 'bg-apple-green/10 text-apple-green' 
        : 'bg-apple-red/10 text-apple-red';
      const animation = type === 'error' ? 'animate-shake' : 'animate-fade-in';
      
      elements.notice.innerHTML = `
        <div class="px-4 py-3 rounded-lg text-sm font-medium mt-4 ${bgColor} ${animation}">
          ${message}
        </div>
      `;
    }

    function clearNotice() {
      elements.notice.innerHTML = '';
    }

    // Loading State
    function setLoading(loading) {
      elements.submitBtn.disabled = loading;
      if (loading) {
        elements.submitBtn.innerHTML = `
          <span>Generating...</span>
          <span class="absolute right-4 top-1/2 -translate-y-1/2 w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin-custom"></span>
        `;
      } else {
        elements.submitBtn.textContent = '缩短';
      }
    }
  </script>
</body>
</html>
`
      
      return new Response(html, {
        headers: {
          "content-type": "text/html;charset=UTF-8",
        },
      })
    }
  
    // Retrieve the target URL
    const value = await LINKS.get(path)
    let location
  
    if (params) {
      location = value + params
    } else {
      location = value
    }
    console.log(value)
  
    if (location) {
      // CAPTCHA validation for link access
      if (isCaptchaRequired('access')) {
        const captchaToken = await extractCaptchaToken(request)
        
        if (!captchaToken) {
          // Return CAPTCHA challenge page
          const captchaPage = `
  <!DOCTYPE html>
  <html lang="en">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verification Required</title>
    <script src="https://captcha.gurl.eu.org/cap.min.js"></script>
    <style>
      body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif; 
             display: flex; justify-content: center; align-items: center; min-height: 100vh; 
             margin: 0; background: linear-gradient(45deg, rgba(14, 46, 75, 1.000) 0.000%, rgba(14, 46, 75, 1.000) 7.692%, rgba(19, 52, 84, 1.000) 7.692%, rgba(19, 52, 84, 1.000) 15.385%, rgba(25, 58, 94, 1.000) 15.385%, rgba(25, 58, 94, 1.000) 23.077%, rgba(31, 65, 104, 1.000) 23.077%, rgba(31, 65, 104, 1.000) 30.769%, rgba(38, 72, 115, 1.000) 30.769%, rgba(38, 72, 115, 1.000) 38.462%, rgba(45, 79, 126, 1.000) 38.462%, rgba(45, 79, 126, 1.000) 46.154%, rgba(52, 86, 138, 1.000) 46.154%, rgba(52, 86, 138, 1.000) 53.846%, rgba(59, 93, 150, 1.000) 53.846%, rgba(59, 93, 150, 1.000) 61.538%, rgba(67, 101, 163, 1.000) 61.538%, rgba(67, 101, 163, 1.000) 69.231%, rgba(75, 109, 176, 1.000) 69.231%, rgba(75, 109, 176, 1.000) 76.923%, rgba(83, 117, 188, 1.000) 76.923%, rgba(83, 117, 188, 1.000) 84.615%, rgba(91, 125, 201, 1.000) 84.615%, rgba(91, 125, 201, 1.000) 92.308%, rgba(99, 134, 214, 1.000) 92.308% 100.000%) }
      .container { background: white; padding: 2rem; border-radius: 10px; box-shadow: 0 10px 40px rgba(0,0,0,0.1); 
                   max-width: 400px; text-align: center; }
      h1 { color: #333; margin-bottom: 1rem; font-size: 1.5rem; }
      p { color: #666; margin-bottom: 2rem; }
      #cap { margin: 2rem 0; display: flex; justify-content: center;}
      .loading { display: none; color: #667eea; margin-top: 1rem; }
    </style>
  </head>
  <body>
    <div class="container">
      <h1>🔒 Verification Required</h1>
      <p>Please complete the CAPTCHA below to access this link.</p>
      
      <cap-widget id="cap" data-cap-api-endpoint="https://captcha.gurl.eu.org/api/"></cap-widget>
      
      <div class="loading" id="loading">Verifying and redirecting...</div>
    </div>
  
    <script>
      const widget = document.querySelector("#cap");
      const loading = document.getElementById("loading");
      
      widget.addEventListener("solve", async function (e) {
        const token = e.detail.token;
        loading.style.display = "block";
        
        // Redirect with token
        window.location.href = window.location.pathname + "?captcha_token=" + encodeURIComponent(token);
      });
    </script>
  </body>
  </html>`
          
          return new Response(captchaPage, {
            headers: {
              "content-type": "text/html;charset=UTF-8",
            },
            status: 403
          })
        }
  
        const validation = await validateCaptchaToken(captchaToken, false)
        
        if (!validation.success) {
          return new Response(`
  <!DOCTYPE html>
  <html>
  <head><title>Verification Failed</title></head>
  <body>
    <h1>❌ Verification Failed</h1>
    <p>${validation.error || 'CAPTCHA verification failed'}</p>
    <a href="${requestURL.pathname}">Try again</a>
  </body>
  </html>`, {
            headers: {
              "content-type": "text/html;charset=UTF-8",
            },
            status: 403
          })
        }
  
        if (validation.degraded) {
          console.warn("Access granted under CAPTCHA service degradation")
        }
      }
  
      // Safe browsing check
      if (config.safe_browsing_api_key) {
        if (!(await is_url_safe(location))) {
          let warning_page = await fetch("https://xytom.github.io/Url-Shorten-Worker/safe-browsing.html")
          warning_page = await warning_page.text()
          warning_page = warning_page.replace(/{Replace}/gm, location)
          return new Response(warning_page, {
            headers: {
              "content-type": "text/html;charset=UTF-8",
            },
          })
        }
      }
  
      // Redirect to target URL
      if (config.no_ref == "on") {
        let no_ref = await fetch("https://xytom.github.io/Url-Shorten-Worker/no-ref.html")
        no_ref = await no_ref.text()
        no_ref = no_ref.replace(/{Replace}/gm, location)
        return new Response(no_ref, {
          headers: {
            "content-type": "text/html;charset=UTF-8",
          },
        })
      } else {
        return Response.redirect(location, 302)
      }
    }
    
    // If request not in kv, return 404
    return new Response(html404, {
      headers: {
        "content-type": "text/html;charset=UTF-8",
      },
      status: 404
    })
  }
  
  
  
  addEventListener("fetch", async event => {
    event.respondWith(handleRequest(event.request))
  })
