<?php
declare(strict_types=1);

namespace BcWafExclusion\Event;

use BaserCore\Event\BcControllerEventListener;
use BaserCore\Utility\BcUtil;
use Cake\Core\Configure;
use Cake\Event\EventInterface;
use Cake\Routing\Router;
use Cake\View\View;

/**
 * BcWafExclusionControllerEventListener
 *
 * 管理画面へのアクセスをフックし、設定オブジェクトおよびフロントマネージャーJSを安全にロードする
 *
 * @package    BcWafExclusion
 * @subpackage Event
 * @author     HATTA <https://hattantoco.com>
 * @license    MIT License
 * @link       https://github.com/hattantoco
 */
class BcWafExclusionControllerEventListener extends BcControllerEventListener
{
    /**
     * 登録するイベント
     *
     * @var array<string, string>
     */
    public $events = [
        'View.beforeRender' => 'onBeforeRender',
    ];

    /**
     * フレームワークへイベントを登録
     *
     * @return array<string, string>
     */
    public function implementedEvents(): array
    {
        return [
            'View.beforeRender' => 'onBeforeRender',
        ];
    }

    /**
     * 管理画面の全ページ描画時にフロントマネージャーJSを安全にロード
     */
    public function onBeforeRender(EventInterface $event): void
    {
        /** @var View $view */
        $view = $event->getSubject();
        $request = $view->getRequest();

        if ($request->getParam('prefix') === 'Admin' && $this->isAuthorizedAdmin()) {
            $apiUrl = Router::url([
                'prefix' => 'Admin',
                'plugin' => 'BcWafExclusion',
                'controller' => 'BcWafExclusionApi',
                'action' => 'beacon',
            ]);
            $resetUrl = Router::url([
                'prefix' => 'Admin',
                'plugin' => 'BcWafExclusion',
                'controller' => 'BcWafExclusion',
                'action' => 'resetAll',
            ]);
            $csrfToken = (string)$request->getAttribute('csrfToken');

            $configScript = sprintf(
                '<script>window.BcWafExclusionConfig = %s;</script>',
                json_encode([
                    'apiUrl' => $apiUrl,
                    'resetUrl' => $resetUrl,
                    'csrfToken' => $csrfToken,
                ], JSON_UNESCAPED_SLASHES)
            );

            $view->append('script', $configScript);
            $view->BcBaser->js('BcWafExclusion.waf_front_manager', false);
        }
    }

    /**
     * ログイン中の管理者が許可対象グループに属しているか検証する
     */
    private function isAuthorizedAdmin(): bool
    {
        $loginUser = BcUtil::loginUser();
        if (!$loginUser) {
            return false;
        }

        // システム管理者（ID: 1）は常に許可
        if (method_exists($loginUser, 'isAdmin') && $loginUser->isAdmin()) {
            return true;
        }

        $targetGroupIds = (array)(Configure::read('BcWafExclusion.target_group_ids') ?? array(1));
        $targetGroupIds = array_map('intval', $targetGroupIds);
        if (!in_array(1, $targetGroupIds, true)) {
            $targetGroupIds[] = 1;
        }

        if (!empty($loginUser->user_groups)) {
            foreach ($loginUser->user_groups as $group) {
                if (in_array((int)$group->id, $targetGroupIds, true)) {
                    return true;
                }
            }
        }

        return false;
    }
}
