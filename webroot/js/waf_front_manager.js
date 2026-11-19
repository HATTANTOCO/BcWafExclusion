/**
 * waf_front_manager.js
 *
 * 管理画面の裏側で自律的に動作し、WAF除外の生存維持、ログイン・ログアウト状態に応じた
 * 自動IP登録および安全な一括パージを制御するフロントマネージャーJavaScript（baserCMS 5系対応版）
 *
 * @package    BcWafExclusion
 * @author     HATTA <https://hattantoco.com>
 * @license    MIT License
 * @link       https://github.com/hattantoco
 */
(function(window) {
    'use strict';

    var WafFrontManager = function(options) {
        this.initialize(options);
    };

    WafFrontManager.prototype = {
        settings: {
            apiUrl: '',
            resetUrl: ''
        },

        initialize: function(options) {
            var config = window.BcWafExclusionConfig || {};
            if (config.apiUrl && config.resetUrl) {
                this.settings.apiUrl = config.apiUrl;
                this.settings.resetUrl = config.resetUrl;
            } else {
                var match = window.location.pathname.match(/^(.*?\/baser\/[^\/]+)/);
                var adminBase = (match && match[1]) ? match[1] : '/baser/admin';
                this.settings.apiUrl = adminBase + '/bc-waf-exclusion/bc-waf-exclusion-api/beacon';
                this.settings.resetUrl = adminBase + '/bc-waf-exclusion/bc-waf-exclusion/reset-all';
            }

            this.bindEvents();
            this.start();
        },

        getCsrfToken: function() {
            if (window.BcWafExclusionConfig && window.BcWafExclusionConfig.csrfToken) {
                return window.BcWafExclusionConfig.csrfToken;
            }
            var cookies = document.cookie ? document.cookie.split(';') : [];
            for (var i = 0; i < cookies.length; i++) {
                var cookie = cookies[i].trim();
                if (cookie.indexOf('csrfToken=') === 0) {
                    return decodeURIComponent(cookie.substring('csrfToken='.length));
                }
            }
            return '';
        },

        fetchInterval: function() {
            var self = this;
            var formData = new FormData();
            formData.append('waf_get_interval', '1');

            fetch(self.settings.apiUrl, {
                method: 'POST',
                credentials: 'same-origin',
                headers: {
                    'X-Requested-With': 'XMLHttpRequest',
                    'X-CSRF-Token': self.getCsrfToken()
                },
                body: formData
            })
            .then(function(response) {
                if (!response.ok) {
                    console.log('[BcWafExclusion Debug] Access denied or session expired (Status:', response.status, '). Stopping execution.');
                    return null;
                }
                return response.json();
            })
            .then(function(res) {
                if (!res) return;

                console.log('[BcWafExclusion Debug] Interval Fetch SUCCESS:', res);

                if (res && res.status === 'missing') {
                    var currentPath = window.location.pathname;
                    if (currentPath.indexOf('/users/login') !== -1 || currentPath.indexOf('login') !== -1) {
                        console.log('[BcWafExclusion Debug] Login page detected. Beacon request skipped.');
                        return;
                    }
                    self.sendBeacon();
                }
            })
            .catch(function(error) {
                console.error('[BcWafExclusion Debug] Interval Fetch ERROR:', error);
            });
        },

        sendBeacon: function(reloadAfter) {
            var self = this;
            var formData = new FormData();
            formData.append('waf_action_beacon', '1');

            fetch(self.settings.apiUrl, {
                method: 'POST',
                credentials: 'same-origin',
                headers: {
                    'X-Requested-With': 'XMLHttpRequest',
                    'X-CSRF-Token': self.getCsrfToken()
                },
                body: formData
            })
            .then(function(response) {
                if (!response.ok) return null;
                return response.json();
            })
            .then(function(res) {
                if (res) {
                    console.log('[BcWafExclusion Debug] Beacon Registration SUCCESS:', res);
                    if (reloadAfter) {
                        window.location.reload();
                    }
                }
            })
            .catch(function(error) {
                console.error('[BcWafExclusion Debug] Beacon Registration ERROR:', error);
            });
        },

        bindEvents: function() {
            var self = this;

            window.addEventListener('click', function(e) {
                var target = e.target.closest('a');
                if (!target) return;

                if (target.dataset.wafActionPassed === 'true') {
                    return;
                }

                var href = target.getAttribute('href') || '';
                var onclickAttr = target.getAttribute('onclick') || '';

                var formId = target.getAttribute('data-post-link-form-id');
                var postForm = formId ? (document.querySelector('form[name="' + formId + '"]') || document.getElementById(formId)) : null;
                var formAction = postForm ? (postForm.getAttribute('action') || '') : '';

                var isLogout = (
                    href.indexOf('users/logout') !== -1 ||
                    href.indexOf('Users/logout') !== -1 ||
                    onclickAttr.indexOf('users/logout') !== -1 ||
                    onclickAttr.indexOf('Users/logout') !== -1 ||
                    formAction.indexOf('users/logout') !== -1 ||
                    formAction.indexOf('Users/logout') !== -1
                );

                var isDetachAction = false;
                if (
                    formAction.indexOf('detach') !== -1 &&
                    (formAction.indexOf('BcWafExclusion') !== -1 || formAction.indexOf('bc-waf-exclusion') !== -1)
                ) {
                    isDetachAction = true;
                }

                if (isLogout || isDetachAction) {
                    e.stopImmediatePropagation();
                    e.stopPropagation();
                    e.preventDefault();

                    if (isDetachAction) {
                        var isConfirm = confirm(
                            'BcWafExclusion の無効化準備として、.htaccess に登録されているWAF除外設定をすべて消去します。\n' +
                            '（※OKを押すと、続けてシステム標準の無効化確認ダイアログが表示されます）\n\n' +
                            '続行してもよろしいですか？'
                        );
                        if (!isConfirm) {
                            return;
                        }
                    }

                    var formData = new FormData();
                    formData.append('waf_delete_beacon', '1');

                    fetch(self.settings.resetUrl, {
                        method: 'POST',
                        credentials: 'same-origin',
                        headers: {
                            'X-Requested-With': 'XMLHttpRequest',
                            'X-CSRF-Token': self.getCsrfToken()
                        },
                        body: formData
                    })
                    .then(function() {
                        target.dataset.wafActionPassed = 'true';
                        target.click();
                    })
                    .catch(function() {
                        target.dataset.wafActionPassed = 'true';
                        target.click();
                    });
                }
            }, true);

            if (typeof document.hidden !== 'undefined') {
                document.addEventListener('visibilitychange', function() {
                    if (!document.hidden) {
                        self.fetchInterval();
                    }
                });
            }
        },

        start: function() {
            if (document.getElementById('waf-just-saved') !== null) {
                this.sendBeacon(true);
                return;
            }
            this.fetchInterval();
        }
    };

    document.addEventListener('DOMContentLoaded', function() {
        window.BcWafFrontManager = new WafFrontManager();
    });

})(window);
