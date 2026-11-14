<?php
declare(strict_types=1);

use MailServer\Management as M;

$phase = 'input';
$database = null;
$committing = false;
try {
    $input = json_decode(stream_get_contents(STDIN, 8193), true, 16, JSON_THROW_ON_ERROR);
    if (!is_array($input) || array_keys($input) !== ['email', 'password', 'repeat']
        || !filter_var($input['email'], FILTER_VALIDATE_EMAIL)) {
        throw new RuntimeException('bootstrap_input');
    }
    require '/opt/mail-management/candidates/protection-relay-v1/bootstrap.php';
    $hash = (new M\AdminPasswordEncoder())->encode($input['password'], $input['repeat'], false);
    $database = new PDO('mysql:unix_socket=/run/mysqld/mysqld.sock;dbname=mail_management;charset=utf8mb4',
        'root', '', [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_EMULATE_PREPARES => false]);
    $phase = 'transaction';
    $database->beginTransaction();
    foreach (['alias_namespace', 'admin_roles'] as $name) {
        $query = $database->prepare('SELECT name FROM mail_management_locks WHERE name=? FOR UPDATE');
        $query->execute([$name]);
        if ($query->fetchColumn() !== $name) { throw new RuntimeException('bootstrap_lock'); }
    }
    foreach (['mail_admin_users', 'mail_admin_credentials', 'mail_admin_audit'] as $table) {
        if ((int) $database->query('SELECT COUNT(*) FROM ' . $table)->fetchColumn() !== 0) {
            throw new RuntimeException('bootstrap_not_empty');
        }
    }
    $phase = 'insert';
    $query = $database->prepare('INSERT INTO mail_admin_users(email,password_hash,user_handle,active,is_system_admin,auth_epoch) VALUES(?,?,?,1,1,1)');
    $query->execute([$input['email'], $hash, random_bytes(32)]);
    $id = $database->lastInsertId();
    $query = $database->prepare('INSERT INTO mail_admin_audit(admin_id,action,target_type,target_id) VALUES(?,?,?,?)');
    $query->execute([$id, 'bootstrap_admin', 'admin', $id]);
    $phase = 'commit';
    $committing = true;
    $database->commit();
    echo json_encode(['status' => 'ok', 'administrator_created' => true, 'passkey_created' => false,
        'administrator' => ['id' => (string) $id, 'email' => $input['email'],
            'password_fingerprint' => hash('sha256', $hash), 'epoch' => '1']], JSON_THROW_ON_ERROR);
} catch (Throwable $error) {
    if (!$committing && $database instanceof PDO && $database->inTransaction()) {
        try { $database->rollBack(); } catch (Throwable) { $committing = true; }
    }
    echo json_encode(['status' => 'fail', 'phase' => $phase, 'uncertain' => $committing,
        'class' => get_class($error)], JSON_THROW_ON_ERROR);
    exit(1);
}
