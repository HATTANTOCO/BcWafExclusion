<?php
declare(strict_types=1);

namespace BcWafExclusion\Controller\Admin;

use BaserCore\Controller\Admin\BcAdminAppController;
use BaserCore\Utility\BcUtil;
use BcWafExclusion\Service\BcWafExclusionService;
use Cake\Core\Configure;
use Cake\Event\EventInterface;
use Cake\Http\Response;

/**
 * BcWafExclusionApiController
 *
 * フロントJavaScriptからの軽量確認（fetch）およびWAF除外（SiteGuard Lite / ModSecurity）の
 * IP自動登録ビーコンを受け止めるAPI専用コントローラー
 *
 * @package    BcWafExclusion
 * @subpackage Controller\Admin
 * @author     HATTA <https://hattantoco.com>
 * @license    MIT License
 * @link       https://hattantoco.com/hattantoco
 */
class BcWafExclusionApiController extends BcAdminAppController
{
    public function initialize(): void
    {
        parent::initialize();
        // baserCMS 5系のCSRF・FormProtectionによるJSON APIブロックを回避（CSRFトークン自体はミドルウェアで検証済み）
        if ($this->components()->has('FormProtection')) {
            $this->FormProtection->setConfig('validate', false);
        }
    }

    public function beforeFilter(EventInterface $event): void
    {
        parent::beforeFilter($event);

        // 管理画面ログイン済みであれば独自グループ判定に委ねる
        if (BcUtil::loginUser()) {
            $this->Authentication->addUnauthenticatedActions(['beacon']);
        }
    }

    public function beacon(): Response
    {
        $loginUser = BcUtil::loginUser();

        if (!$loginUser || !$this->isAuthorizedUser($loginUser)) {
            return $this->getResponse()
                ->withStatus(403)
                ->withType('application/json')
                ->withStringBody((string)json_encode(['status' => 'forbidden']));
        }

        $status = 'idle';
        $request = $this->getRequest();
        $service = new BcWafExclusionService();

        if (!empty($request->getData('waf_action_beacon'))) {
            $ip = (string)$request->clientIp();
            if ($ip !== '') {
                $service->removeIp($ip);
                $service->updateWafTimestamp($ip);
            }
            $status = 'registered';
        } elseif (!empty($request->getData('waf_get_interval'))) {
            $clientIp = (string)$request->clientIp();
            $status = $service->isIpRegistered($clientIp) ? 'verified' : 'missing';
        }

        return $this->getResponse()
            ->withType('application/json')
            ->withStringBody((string)json_encode([
                'status' => $status,
            ]));
    }

    private function isAuthorizedUser(mixed $loginUser): bool
    {
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
