<?php
declare(strict_types=1);

namespace BcWafExclusion\Controller\Admin;

use BaserCore\Controller\Admin\BcAdminAppController;
use BcWafExclusion\Service\BcWafExclusionService;
use Cake\Core\Configure;
use Cake\Core\Plugin;
use Cake\Http\Response;

/**
 * BcWafExclusionController
 *
 * WAF除外（SiteGuard Lite / ModSecurity）の設定保存、環境診断表示、手動クリアを制御するコントローラー
 * 
 * @package    BcWafExclusion
 * @subpackage Controller\Admin
 * @author     HATTA <https://hattantoco.com>
 * @license    MIT License
 * @link       https://github.com/HATTANTOCO
 */
class BcWafExclusionController extends BcAdminAppController
{
    public function initialize(): void
    {
        parent::initialize();
        if ($this->components()->has('FormProtection')) {
            $this->FormProtection->setConfig('unlockedActions', ['resetAll']);
        }
    }

    public function index(): ?Response
    {
        $this->setTitle(__d('bc_waf_exclusion', 'WAF除外コントローラ設定'));

        $userGroupsTable = $this->fetchTable('BaserCore.UserGroups');
        $userGroups = $userGroupsTable->find('list', keyField: 'id', valueField: 'title')
            ->orderBy(['UserGroups.id' => 'ASC'])
            ->toArray();
        $this->set('userGroups', $userGroups);

        $service = new BcWafExclusionService();
        $htaccessPath = $service->getHtaccessPath();

        if ($this->getRequest()->is(['post', 'put'])) {
            $formData = $this->getRequest()->getData('BcWafExclusion');
            if (is_array($formData)) {
                $wafType = (isset($formData['waf_type']) && in_array($formData['waf_type'], ['siteguard', 'modsec'], true))
                    ? $formData['waf_type']
                    : 'siteguard';

                $newGroups = isset($formData['target_group_ids']) ? (array)$formData['target_group_ids'] : [];
                $newGroups = array_map('intval', $newGroups);
                if (!in_array(1, $newGroups, true)) {
                    array_unshift($newGroups, 1);
                }
                $newGroups = array_values(array_unique($newGroups));

                $forceWaf = (isset($formData['force_waf']) && $formData['force_waf'] === '1');

                if ($this->saveSettingFile($wafType, $newGroups, $forceWaf)) {
                    Configure::write('BcWafExclusion.waf_type', $wafType);
                    Configure::write('BcWafExclusion.target_group_ids', $newGroups);
                    Configure::write('BcWafExclusion.force_waf', $forceWaf);

                    // WAF種別や設定変更を即時反映させるため、既存ブロックを一度パージして再登録を促す
                    $service->purgeAll();

                    $this->BcMessage->setSuccess(__d('bc_waf_exclusion', 'WAF除外の設定を保存しました。'));
                    $this->getRequest()->getSession()->write('BcWafExclusion.just_saved', true);

                    return $this->redirect([
                        'plugin' => 'BcWafExclusion',
                        'controller' => 'BcWafExclusion',
                        'action' => 'index',
                    ]);
                } else {
                    $this->BcMessage->setError(__d('bc_waf_exclusion', '設定ファイルの保存に失敗しました。パーミッションを確認してください。'));
                }
            }
        }

        $justSaved = (bool)$this->getRequest()->getSession()->consume('BcWafExclusion.just_saved');
        $this->set('justSaved', $justSaved);
        $this->set('diagnostics', $service->getServerDiagnostics());
        $this->set('clientIp', (string)$this->getRequest()->clientIp());

        $currentSetting = Configure::read('BcWafExclusion') ?? [
            'waf_type' => 'siteguard',
            'target_group_ids' => array(1),
            'force_waf' => false,
        ];
        $this->set('wafConfig', $currentSetting);

        $htaccessContent = '';
        if (file_exists($htaccessPath)) {
            $htaccessContent = (string)file_get_contents($htaccessPath);
        }
        $this->set('htaccessContent', $htaccessContent);

        return null;
    }

    public function resetAll(): ?Response
    {
        $service = new BcWafExclusionService();
        $htaccessPath = $service->getHtaccessPath();

        if ($this->getRequest()->getData('waf_delete_beacon') === '1') {
            $service->purgeAll();

            return $this->getResponse()
                ->withType('application/json')
                ->withStringBody((string)json_encode(['status' => 'success']));
        }

        if (file_exists($htaccessPath) && is_writable($htaccessPath)) {
            if ($service->purgeAll()) {
                $this->getRequest()->getSession()->write('BcWafExclusion.just_saved', true);
                $this->BcMessage->setSuccess(__d('bc_waf_exclusion', 'すべてのWAF除外IPアドレスの登録を一括クリアしました。'));
            } else {
                $this->BcMessage->setError(__d('bc_waf_exclusion', '.htaccess の一括クリア処理に失敗しました。'));
            }
        } else {
            $this->BcMessage->setError(__d('bc_waf_exclusion', '.htaccess ファイルが書き込み不可、または存在しません。'));
        }

        return $this->redirect([
            'plugin' => 'BcWafExclusion',
            'controller' => 'BcWafExclusion',
            'action' => 'index',
        ]);
    }

    private function saveSettingFile(string $wafType, array $groupIds, bool $forceWaf): bool
    {
        $settingPath = Plugin::configPath('BcWafExclusion') . 'setting.php';
        $groupIdsExport = implode(', ', $groupIds);
        $forceWafExport = $forceWaf ? 'true' : 'false';

        $content = <<<PHP
<?php
/**
 * setting.php
 *
 * BcWafExclusionプラグインの設定ファイル（SiteGuard Lite / ModSecurity 統合版）
 *
 * @package    BcWafExclusion
 * @subpackage Config
 * @author     HATTA
 * @license    MIT License
 * @link       https://hattantoco.com
 */

return [
    // プラグイン独自設定
    'BcWafExclusion' => [
        // 使用するWAF種別（'siteguard': SiteGuard Lite / 'modsec': ModSecurity）
        'waf_type' => '{$wafType}',
        // WAFバイパス対象ユーザーグループID（1: システム管理者 は常に強制追加）
        'target_group_ids' => [
            {$groupIdsExport},
        ],
        // ModSecurity強制有効化フラグ（false: 自動判定 / true: 強制出力）
        'force_waf' => {$forceWafExport},
    ],

    // コントローラーイベントリスナーをシステムへ自動登録
    'BcEvent' => [
        'Controller' => [
            'BcWafExclusionControllerEventListener' => [
                'plugin' => 'BcWafExclusion',
                'className' => 'BcWafExclusion\\Event\\BcWafExclusionControllerEventListener'
            ]
        ]
    ]
];

PHP;

        return file_put_contents($settingPath, $content, LOCK_EX) !== false;
    }
}
