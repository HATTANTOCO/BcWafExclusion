<?php
return [
    'type' => 'Plugin',
    'title' => __d('bc_waf_exclusion', 'WAF自動バイパス（BcWafExclusion）'),
    'description' => __d('bc_waf_exclusion', 'WAF（SiteGuard Lite / ModSecurity）による403誤検知を解決するため、管理画面操作中の対象ユーザーのIPアドレスのみを一時的に動的バイパスします。'),
    'author' => 'HATTA',
    'url' => 'https://hattantoco.com',
    'adminLink' => ['plugin' => 'BcWafExclusion', 'controller' => 'BcWafExclusion', 'action' => 'index'],
    'installMessage' => __d('bc_waf_exclusion', '利用前に書き込み対象となる .htaccess（または webroot/.htaccess）に書き込み権限があるか確認してください。')
];
