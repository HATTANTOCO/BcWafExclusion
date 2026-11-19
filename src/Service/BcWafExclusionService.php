<?php
declare(strict_types=1);

namespace BcWafExclusion\Service;

use Cake\Core\Configure;

/**
 * BcWafExclusionService
 *
 * .htaccess への WAF（SiteGuard Lite / ModSecurity）除外ディレクティブの
 * 書き込み・検証・削除・環境診断を統合管理するサービス
 * 
 * @package    BcWafExclusion
 * @subpackage Service
 * @author     HATTA <https://hattantoco.com>
 * @license    MIT License
 * @link       https://github.com/HATTANTOCO
 */
class BcWafExclusionService
{
    private string $htaccessPath;

    public function __construct(?string $htaccessPath = null)
    {
        $this->htaccessPath = $htaccessPath ?? $this->resolveTargetHtaccessPath();
    }

    public function getHtaccessPath(): string
    {
        return $this->htaccessPath;
    }

    private function resolveTargetHtaccessPath(): string
    {
        $rootHtaccess = ROOT . DS . '.htaccess';
        $webrootHtaccess = WWW_ROOT . '.htaccess';

        $docRoot = isset($_SERVER['DOCUMENT_ROOT']) ? rtrim((string)realpath($_SERVER['DOCUMENT_ROOT']), '/\\') : '';
        $webRoot = rtrim((string)realpath(WWW_ROOT), '/\\');
        if ($docRoot !== '' && $docRoot === $webRoot) {
            return $webrootHtaccess;
        }

        if (file_exists($rootHtaccess)) {
            $rootContent = (string)file_get_contents($rootHtaccess);
            if (str_contains($rootContent, 'webroot/')) {
                return $rootHtaccess;
            }
        }

        return $webrootHtaccess;
    }

    /**
     * 現在の設定値（waf_type / force_waf）およびサーバー環境を診断する
     *
     * @return array<string, mixed>
     */
    public function getServerDiagnostics(): array
    {
        $wafType = (string)(Configure::read('BcWafExclusion.waf_type') ?? 'siteguard');
        if (!in_array($wafType, ['siteguard', 'modsec'], true)) {
            $wafType = 'siteguard';
        }

        $serverSoftware = (string)($_SERVER['SERVER_SOFTWARE'] ?? '');
        $apacheVersion = '0.0.0';
        if (preg_match('/Apache\/([0-9\.]+)/', $serverSoftware, $matches)) {
            $apacheVersion = $matches[1];
        }

        if (function_exists('apache_get_modules')) {
            $modules = apache_get_modules();
            $hasModSecurity = (in_array('mod_security2', $modules, true) || in_array('security2_module', $modules, true));
        } else {
            $hasModSecurity = (
                stripos($serverSoftware, 'ModSecurity') !== false ||
                stripos($serverSoftware, 'mod_security') !== false
            );
        }

        $isApacheOk = version_compare($apacheVersion, '2.4.26', '>=');
        $forceWaf = (bool)(Configure::read('BcWafExclusion.force_waf') ?? false);
        $isHtaccessWritable = (file_exists($this->htaccessPath) && is_writable($this->htaccessPath));

        if ($wafType === 'modsec') {
            $isWafUpdatable = (($isApacheOk && $hasModSecurity) || $forceWaf);
        } else {
            // SiteGuard Lite は <IfModule mod_siteguard.c> により安全に動作するため常に有効
            $isWafUpdatable = true;
        }

        // パーミッションの安全性チェック（Unix系OSのみ判定：その他ユーザーに書き込み権限 0002 がある場合は危険）
        $htaccessPerms = '';
        $isPermsUnsafe = false;
        if (file_exists($this->htaccessPath) && DIRECTORY_SEPARATOR === '/') {
            clearstatcache(true, $this->htaccessPath);
            $perms = @fileperms($this->htaccessPath);
            if ($perms !== false) {
                $htaccessPerms = substr(sprintf('%o', $perms), -3);
                if (($perms & 0x0002) !== 0) {
                    $isPermsUnsafe = true;
                }
            }
        }

        return [
            'wafType' => $wafType,
            'serverSoftware' => $serverSoftware,
            'apacheVersion' => $apacheVersion,
            'isApacheOk' => $isApacheOk,
            'hasModSecurity' => $hasModSecurity,
            'forceWaf' => $forceWaf,
            'isWafUpdatable' => $isWafUpdatable,
            'isHtaccessWritable' => $isHtaccessWritable,
            'htaccessPath' => $this->htaccessPath,
            'htaccessPerms' => $htaccessPerms,
            'isPermsUnsafe' => $isPermsUnsafe,
        ];
    }

    /**
     * 指定されたIPアドレスが現在のWAF種別の形式で .htaccess に登録済みか確認する
     */
    public function isIpRegistered(string $ip): bool
    {
        if (!filter_var($ip, FILTER_VALIDATE_IP) || !file_exists($this->htaccessPath)) {
            return false;
        }

        $diagnostics = $this->getServerDiagnostics();
        if (!$diagnostics['isWafUpdatable']) {
            // 待機中（自動判定条件未達）の場合は書き込みスキップのため verified 扱いとする
            return true;
        }

        $content = (string)file_get_contents($this->htaccessPath);
        if ($diagnostics['wafType'] === 'modsec') {
            return str_contains($content, "REMOTE_ADDR} == '{$ip}'");
        }

        return str_contains($content, "SiteGuard_User_ExcludeSig ip({$ip})");
    }

    /**
     * 選択されているWAF種別に応じた除外ディレクティブブロックを生成する
     */
    public function generateWafDirective(string $ip, string $wafType = 'siteguard'): string
    {
        if ($wafType === 'modsec') {
            return "# --- WAF_EXCLUSION_START ---\n" .
                   "<IfModule mod_security2.c>\n" .
                   "  <If \"%{REMOTE_ADDR} == '{$ip}'\">\n" .
                   "    SecFilterEngine Off\n" .
                   "    SecRuleEngine Off\n" .
                   "  </If>\n" .
                   "</IfModule>\n" .
                   "# --- WAF_EXCLUSION_END ---\n";
        }

        return "# --- WAF_EXCLUSION_START ---\n" .
               "<IfModule mod_siteguard.c>\n" .
               "  SiteGuard_User_ExcludeSig ip({$ip})\n" .
               "</IfModule>\n" .
               "# --- WAF_EXCLUSION_END ---\n";
    }

    /**
     * 指定されたIPアドレスのブロックを .htaccess へ書き込み・更新する
     * 選択されていない別種別のWAFブロックが残っていた場合はすべて即座にパージする
     */
    public function updateWafTimestamp(string $ip): bool
    {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return false;
        }

        $diagnostics = $this->getServerDiagnostics();

        // 1. 選択されていない別種別のWAFブロックが残っていた場合は条件に関わらず即座にパージ
        if (file_exists($this->htaccessPath) && is_writable($this->htaccessPath)) {
            $currentContent = (string)file_get_contents($this->htaccessPath);
            $otherModule = ($diagnostics['wafType'] === 'modsec') ? 'mod_siteguard\.c' : 'mod_security2\.c';
            $otherPattern = '/\R*# --- WAF_EXCLUSION_START ---\R*<IfModule ' . $otherModule . '>.*?# --- WAF_EXCLUSION_END ---\R*/s';
            $cleanedContent = (string)preg_replace($otherPattern, "\n", $currentContent);
            if ($cleanedContent !== $currentContent) {
                $cleanedContent = (string)preg_replace('/(?:\r\n|\r|\n){3,}/', "\n\n", $cleanedContent);
                $cleanedContent = ltrim($cleanedContent, "\r\n");
                file_put_contents($this->htaccessPath, $cleanedContent, LOCK_EX);
                clearstatcache(true, $this->htaccessPath);
            }
        }

        // 2. 書き込み可否（ModSecurityの自動判定条件含む）チェック
        if (!$diagnostics['isWafUpdatable'] || !$diagnostics['isHtaccessWritable']) {
            return false;
        }

        $content = (string)file_get_contents($this->htaccessPath);

        // 3. 既に同一IPのブロックがあれば一旦除去（重複防止）
        $pattern = '/\R*# --- WAF_EXCLUSION_START ---.*?' . preg_quote($ip, '/') . '.*?# --- WAF_EXCLUSION_END ---\R*/s';
        $content = (string)preg_replace($pattern, "\n", $content);

        // 4. 現在選択されているWAF種別のブロックを生成して挿入
        $directive = $this->generateWafDirective($ip, $diagnostics['wafType']);

        $marker = '# [WAF_EXCLUSION_MARKER]';
        if (str_contains($content, $marker)) {
            $content = str_replace($marker, $marker . "\n\n" . $directive, $content);
        } else {
            $content = $directive . ltrim($content, "\r\n");
        }

        $content = (string)preg_replace('/(?:\r\n|\r|\n){3,}/', "\n\n", $content);
        $content = ltrim($content, "\r\n");

        $result = file_put_contents($this->htaccessPath, $content, LOCK_EX);
        clearstatcache(true, $this->htaccessPath);

        return $result !== false;
    }

    /**
     * 指定されたIPアドレスのブロックを削除する
     */
    public function removeIp(string $ip): bool
    {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return false;
        }
        if (!file_exists($this->htaccessPath) || !is_writable($this->htaccessPath)) {
            return false;
        }

        $content = (string)file_get_contents($this->htaccessPath);

        $pattern = '/\R*# --- WAF_EXCLUSION_START ---.*?' . preg_quote($ip, '/') . '.*?# --- WAF_EXCLUSION_END ---\R*/s';
        $content = (string)preg_replace($pattern, "\n", $content);
        $content = (string)preg_replace('/(?:\r\n|\r|\n){3,}/', "\n\n", $content);
        $content = ltrim($content, "\r\n");

        $result = file_put_contents($this->htaccessPath, $content, LOCK_EX);
        clearstatcache(true, $this->htaccessPath);

        return $result !== false;
    }

    /**
     * .htaccess 内のすべての WAF_EXCLUSION ブロックを一括全消去（パージ）する
     */
    public function purgeAll(): bool
    {
        if (!file_exists($this->htaccessPath) || !is_writable($this->htaccessPath)) {
            return false;
        }

        $content = (string)file_get_contents($this->htaccessPath);

        $pattern = '/\R*# --- WAF_EXCLUSION_START ---.*?# --- WAF_EXCLUSION_END ---\R*/s';
        $content = (string)preg_replace($pattern, "\n", $content);
        $content = (string)preg_replace('/(?:\r\n|\r|\n){3,}/', "\n\n", $content);
        $content = ltrim($content, "\r\n");

        $result = file_put_contents($this->htaccessPath, $content, LOCK_EX);
        clearstatcache(true, $this->htaccessPath);

        return $result !== false;
    }
}
