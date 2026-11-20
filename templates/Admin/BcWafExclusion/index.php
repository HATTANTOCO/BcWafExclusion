<?php
/**
 * index.php
 *
 * WAF除外（SiteGuard Lite / ModSecurity）の設定・環境診断・.htaccessプレビューを行う管理画面ビュー
 *
 * @package    BcWafExclusion
 * @subpackage View
 * @author     HATTA <https://hattantoco.com>
 * @license    MIT License
 * @link       https://github.com/hattantoco
 * 
 * @var \BaserCore\View\BcAdminAppView $this
 * @var array<int, string> $userGroups
 * @var array<string, mixed> $wafConfig
 * @var array<string, mixed> $diagnostics
 * @var string $clientIp
 * @var string $htaccessContent
 * @var bool $justSaved
 */
$wafType = $wafConfig['waf_type'] ?? 'siteguard';
$selectedGroups = $wafConfig['target_group_ids'] ?? array(1);
$forceWafValue = !empty($wafConfig['force_waf']) ? '1' : '0';
$isModSec = ($wafType === 'modsec');
?>

<?php if (!empty($justSaved)): ?>
<span id="waf-just-saved" style="display:none;"></span>
<?php endif; ?>

<div class="bc-heading">
    <h2><?php echo __d('bc_waf_exclusion', 'WAF除外コントローラ設定') ?></h2>
</div>

<?php echo $this->BcAdminForm->create(null) ?>

<!-- 1. 対象ユーザーグループ -->
<table class="form-table section bca-form-table">
    <tr>
        <th class="col-head bca-form-table__label">
            <?php echo $this->BcAdminForm->label('BcWafExclusion.target_group_ids', __d('bc_waf_exclusion', '対象ユーザーグループ')) ?>
        </th>
        <td class="col-input bca-form-table__input">
            <?php echo $this->BcAdminForm->control('BcWafExclusion.target_group_ids', [
                'type' => 'multiCheckbox',
                'options' => $userGroups,
                'value' => $selectedGroups,
                'label' => false,
                'onclick' => "if(this.value=='1'){return false;}"
            ]) ?>
            <br>
            <small><?php echo __d('bc_waf_exclusion', 'WAF自動バイパスの対象（IPアドレスを自動登録するグループ）を選択してください。') ?></small>
        </td>
    </tr>
</table>

<!-- 2. サーバー環境診断ステータス（グレーのボックス枠） -->
<div style="background-color: #f8f9fa; border: 1px solid #dee2e6; padding: 15px 20px; border-radius: 4px; margin: 20px 0;">
    <h3 style="margin-top: 0; margin-bottom: 12px; font-size: 1.05em;"><?php echo __d('bc_waf_exclusion', 'サーバー環境診断ステータス') ?></h3>
    <ul style="padding-left: 20px; line-height: 1.7; margin-bottom: 12px;">
        <li><strong><?php echo __d('bc_waf_exclusion', '現在の接続元IPアドレス:') ?></strong> <code><?php echo h($clientIp); ?></code></li>
        <?php
        $targetLabel = str_starts_with((string)$diagnostics['htaccessPath'], WWW_ROOT)
            ? __d('bc_waf_exclusion', 'webroot/.htaccess（baserCMSのインストールルート配下の webroot 内）')
            : __d('bc_waf_exclusion', '.htaccess（baserCMSのインストールルート直下）');
        ?>
        <li>
            <strong><?php echo __d('bc_waf_exclusion', '書き込み対象ファイル:') ?></strong> <code><?php echo h($targetLabel); ?></code>
            <?php if (!empty($diagnostics['isHtaccessWritable'])): ?>
                <?php if (!empty($diagnostics['isPermsUnsafe'])): ?>
                    <span style="color: #dc3545; font-weight: bold;">
                        <?php echo __d('bc_waf_exclusion', '（警告：危険なパーミッション {0} です。安全のため 604 や 644 などに変更してください）', h($diagnostics['htaccessPerms'])) ?>
                    </span>
                <?php else: ?>
                    <span style="color: #28a745; font-weight: bold;">
                        <?php echo !empty($diagnostics['htaccessPerms'])
                            ? __d('bc_waf_exclusion', '（書き込み可能 / パーミッション: {0}）', h($diagnostics['htaccessPerms']))
                            : __d('bc_waf_exclusion', '（書き込み可能）'); ?>
                    </span>
                <?php endif; ?>
            <?php else: ?>
                <span style="color: #dc3545; font-weight: bold;"><?php echo __d('bc_waf_exclusion', '（書き込み不可・パーミッションを確認してください）') ?></span>
            <?php endif; ?>
        </li>
        <li class="js-modsec-only" style="<?php echo $isModSec ? '' : 'display: none;'; ?>">
            <strong><?php echo __d('bc_waf_exclusion', '検出されたApacheバージョン:') ?></strong>
            <?php echo h($diagnostics['apacheVersion']); ?>
            <?php if ($diagnostics['isApacheOk']): ?>
                <span style="color: #28a745; font-weight: bold;"><?php echo __d('bc_waf_exclusion', '（2.4.26以上: 条件クリア）') ?></span>
            <?php else: ?>
                <span style="color: #dc3545; font-weight: bold;"><?php echo __d('bc_waf_exclusion', '（2.4.26未満、またはApacheバージョン非公開環境）') ?></span>
            <?php endif; ?>
        </li>
        <li class="js-modsec-only" style="<?php echo $isModSec ? '' : 'display: none;'; ?>">
            <strong><?php echo __d('bc_waf_exclusion', 'ModSecurity（mod_security2）検出:') ?></strong>
            <?php if ($diagnostics['hasModSecurity']): ?>
                <span style="color: #28a745; font-weight: bold;"><?php echo __d('bc_waf_exclusion', '検出済み') ?></span>
            <?php else: ?>
                <span style="color: #6c757d;"><?php echo __d('bc_waf_exclusion', '未検出（または非公開構成）') ?></span>
            <?php endif; ?>
        </li>
    </ul>
    <hr style="border: 0; border-top: 1px solid #dee2e6; margin: 12px 0;">
    <p style="margin-bottom: 0;">
        <strong><?php echo __d('bc_waf_exclusion', '現在の動作ステータス:') ?></strong>
        <?php if (!$diagnostics['isHtaccessWritable']): ?>
            <span style="color: #dc3545; font-weight: bold;"><?php echo __d('bc_waf_exclusion', '停止中（.htaccess に書き込み権限がありません）') ?></span>
        <?php elseif ($diagnostics['isWafUpdatable']): ?>
            <span style="color: #28a745; font-weight: bold;">
                <?php echo __d('bc_waf_exclusion', '有効（{0} 除外ディレクティブを自動書き込みします）', $isModSec ? 'ModSecurity' : 'SiteGuard Lite') ?>
            </span>
        <?php else: ?>
            <span style="color: #dc3545; font-weight: bold;"><?php echo __d('bc_waf_exclusion', '待機中（自動判定条件を満たしていないため .htaccess への書き込みを行いません）') ?></span>
        <?php endif; ?>
    </p>
</div>

<!-- 3. 使用するWAF種別・動作モード -->
<table class="form-table section bca-form-table">
    <tr id="waf-type-row">
        <th class="col-head bca-form-table__label" style="<?php echo $isModSec ? '' : 'border-bottom: none;'; ?>">
            <?php echo $this->BcAdminForm->label('BcWafExclusion.waf_type', __d('bc_waf_exclusion', '使用するWAF種別')) ?>
        </th>
        <td class="col-input bca-form-table__input" style="<?php echo $isModSec ? '' : 'border-bottom: none;'; ?>">
            <?php echo $this->BcAdminForm->control('BcWafExclusion.waf_type', [
                'type' => 'radio',
                'options' => [
                    'siteguard' => __d('bc_waf_exclusion', 'SiteGuard Lite（ロリポップ！・エックスサーバー・さくらのレンタルサーバ等）'),
                    'modsec' => __d('bc_waf_exclusion', 'ModSecurity（Apache 2.4.26以上 + mod_security2 環境）'),
                ],
                'value' => $wafType,
                'label' => false,
            ]) ?>
            <br>
            <small><?php echo __d('bc_waf_exclusion', 'ご利用中のサーバーに導入されているWAFの種類を選択してください。') ?></small>
        </td>
    </tr>
    <tr class="js-modsec-only" style="<?php echo $isModSec ? '' : 'display: none;'; ?>">
        <th class="col-head bca-form-table__label">
            <?php echo $this->BcAdminForm->label('BcWafExclusion.force_waf', __d('bc_waf_exclusion', '動作モード（ModSecurity強制有効化）')) ?>
        </th>
        <td class="col-input bca-form-table__input">
            <?php echo $this->BcAdminForm->control('BcWafExclusion.force_waf', [
                'type' => 'select',
                'options' => [
                    '0' => __d('bc_waf_exclusion', '自動判定（Apache 2.4.26以上 かつ mod_security2 検出時のみ出力）'),
                    '1' => __d('bc_waf_exclusion', '強制有効（バージョンやモジュールが非公開のサーバーでも強制出力）'),
                ],
                'value' => $forceWafValue,
                'label' => false,
            ]) ?>
            <br>
            <small>
                <?php echo __d('bc_waf_exclusion', 'セキュリティ対策等でサーバー情報（ServerTokens等）が隠蔽されており自動判定で「待機中」になる場合は、「強制有効」を選択してください。') ?><br>
                <?php echo __d('bc_waf_exclusion', '※Apache 2.2系や .htaccess 内での SecRuleEngine 記述が禁止されたサーバーで強制有効にすると500エラーになる場合があります。') ?>
            </small>
        </td>
    </tr>
</table>

<!-- 4. 保　存 ボタン -->
<div class="submit bca-actions" style="margin: 20px 0 20px;">
    <div class="bca-actions__main">
        <?php echo $this->BcAdminForm->submit(__d('bc_waf_exclusion', '保　存'), [
            'div' => false,
            'class' => 'button bca-btn bca-actions__item',
            'data-bca-btn-size' => 'lg',
            'data-bca-btn-width' => 'lg',
            'data-bca-btn-type' => 'save'
        ]) ?>
    </div>
</div>

<?php echo $this->BcAdminForm->end() ?>

<div class="section" style="margin-top: 40px; border-top: 1px dashed #ccc; padding-top: 20px;">
    <h2><?php echo __d('bc_waf_exclusion', '手動メンテナンス') ?></h2>

    <div style="margin-bottom: 20px;">
        <p><small><?php echo __d('bc_waf_exclusion', '現在の .htaccess の記述内容（確認用プレビュー）:') ?></small></p>
        <textarea readonly rows="12" style="width: 100%; font-family: Menlo, Courier, monospace; font-size: 1em; line-height: 1.4; padding: 10px; background-color: #f5f5f5; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; resize: vertical;"><?php echo h($htaccessContent); ?></textarea>
    </div>

    <p><small>
        <?php echo __d('bc_waf_exclusion', '現在 .htaccess に登録されているすべてのWAF除外IPを消去（クリア）します。') ?><br>
        <?php echo __d('bc_waf_exclusion', '※クリアを実行後、現在ログイン中のあなたのIPアドレスのみ自動的に再登録されます。') ?>
    </small></p>

    <?php echo $this->BcAdminForm->create(null, [
        'url' => [
            'plugin' => 'BcWafExclusion',
            'controller' => 'BcWafExclusion',
            'action' => 'resetAll'
        ],
        'id' => 'WafExclusionResetForm'
    ]) ?>
    <div class="submit bca-actions">
        <div class="bca-actions__main">
            <?php echo $this->BcAdminForm->submit(__d('bc_waf_exclusion', 'WAF除外IPを全てクリア'), [
                'div' => false,
                'class' => 'button bca-btn bca-actions__item',
                'data-bca-btn-size' => 'lg',
                'onclick' => "return confirm('" . h(__d('bc_waf_exclusion', '現在登録されているすべてのWAF除外IPを削除します。よろしいですか？')) . "');"
            ]) ?>
        </div>
    </div>
    <?php echo $this->BcAdminForm->end() ?>
</div>

<script>
document.addEventListener('DOMContentLoaded', function() {
    var radios = document.querySelectorAll('input[name="BcWafExclusion[waf_type]"]');
    var modsecElements = document.querySelectorAll('.js-modsec-only');

    function toggleModSecFields() {
        var selected = document.querySelector('input[name="BcWafExclusion[waf_type]"]:checked');
        var isModSec = (selected && selected.value === 'modsec');

        modsecElements.forEach(function(el) {
            el.style.display = isModSec ? '' : 'none';
        });

        var wafTypeCells = document.querySelectorAll('#waf-type-row th, #waf-type-row td');
        wafTypeCells.forEach(function(cell) {
            cell.style.borderBottom = isModSec ? '' : 'none';
        });
    }

    radios.forEach(function(radio) {
        radio.addEventListener('change', toggleModSecFields);
    });
});
</script>
