<?php
/**
 * setting.php
 *
 * BcWafExclusionプラグインの設定ファイル（SiteGuard Lite / ModSecurity 統合版）
 *
 * @package    BcWafExclusion
 * @subpackage Config
 * @author     HATTA <https://hattantoco.com>
 * @license    MIT License
 * @link       https://github.com/HATTANTOCO
 */

return [
    // プラグイン独自設定
    'BcWafExclusion' => [
        // 使用するWAF種別（'siteguard': SiteGuard Lite / 'modsec': ModSecurity）
        'waf_type' => 'siteguard',
        // WAFバイパス対象ユーザーグループID（1: システム管理者 は常に強制追加）
        'target_group_ids' => [
            1,
        ],
        // ModSecurity強制有効化フラグ（false: 自動判定 / true: 強制出力）
        'force_waf' => false,
    ],

    // コントローラーイベントリスナーをシステムへ自動登録
    'BcEvent' => [
        'Controller' => [
            'BcWafExclusionControllerEventListener' => [
                'plugin' => 'BcWafExclusion',
                'className' => 'BcWafExclusion\Event\BcWafExclusionControllerEventListener'
            ]
        ]
    ]
];
