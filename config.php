<?php
return [
    'type' => 'Plugin',
    'title' => 'WAF自動バイパス（BcWafExclusion）',
    'description' => 'WAF（SiteGuard Lite / ModSecurity）による403誤検知を解決するため、管理画面操作中の対象ユーザーのIPアドレスのみを一時的に動的バイパスします。',
    'author' => 'HATTA',
    'url' => 'https://hattantoco.com',
    'adminLink' => ['plugin' => 'BcWafExclusion', 'controller' => 'BcWafExclusion', 'action' => 'index'],
    'installMessage' => '利用前に公開ディレクトリ直下の webroot/.htaccess に書き込み権限があるか確認してください。'
];
