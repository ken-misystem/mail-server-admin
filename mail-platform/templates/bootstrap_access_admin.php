<?php
declare(strict_types=1);

use MailServer\Management\AdminPasswordEncoder;

if (PHP_SAPI !== 'cli' || !function_exists('posix_geteuid') || posix_geteuid() !== 0) { exit(1); }
$database = null;
$committing = false;
try {
    $input = json_decode(stream_get_contents(STDIN, 8193), true, 16, JSON_THROW_ON_ERROR);
    if (!is_array($input) || !in_array($input['action'] ?? null, ['check', 'complete', 'reissue'], true)
        || !is_array($input['administrator'] ?? null)) { throw new RuntimeException('setup_input'); }
    require '/opt/mail-management/candidates/protection-relay-v1/bootstrap.php';
    $database = new PDO('mysql:unix_socket=/run/mysqld/mysqld.sock;dbname=mail_management;charset=utf8mb4',
        'root', '', [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_EMULATE_PREPARES => false]);
    $database->beginTransaction();
    $query = $database->prepare('SELECT id,email,password_hash,auth_epoch,active,is_system_admin FROM mail_admin_users WHERE id=? FOR UPDATE');
    $query->execute([$input['administrator']['id']]);
    $row = $query->fetch(PDO::FETCH_ASSOC);
    if (!$row || (string) $row['id'] !== $input['administrator']['id']
        || $row['email'] !== $input['administrator']['email']
        || (string) $row['auth_epoch'] !== $input['administrator']['epoch']
        || !hash_equals($input['administrator']['password_fingerprint'], hash('sha256', $row['password_hash']))
        || (int) $row['active'] !== 1 || (int) $row['is_system_admin'] !== 1) {
        throw new RuntimeException('setup_administrator_changed');
    }
    if ($input['action'] !== 'reissue') {
        $query = $database->prepare('SELECT id,last_used_at FROM mail_admin_credentials WHERE admin_id=? AND enabled=1 FOR UPDATE');
        $query->execute([$row['id']]);
        $verified = false;
        foreach ($query->fetchAll(PDO::FETCH_ASSOC) as $credential) {
            $verified = $verified || $credential['last_used_at'] !== null;
        }
        if (!$verified) { throw new RuntimeException('setup_passkey_verification_required'); }
    }
    if ($input['action'] !== 'check') {
        if (!is_string($input['password'] ?? null) || strlen($input['password']) < 16
            || password_verify($input['password'], $row['password_hash'])) {
            throw new RuntimeException('setup_new_independent_password_required');
        }
        $hash = (new AdminPasswordEncoder())->encode($input['password'], $input['repeat'] ?? '', false);
        $query = $database->prepare('UPDATE mail_admin_users SET password_hash=?,auth_epoch=auth_epoch+1 WHERE id=?');
        $query->execute([$hash, $row['id']]);
        $query = $database->prepare('INSERT INTO mail_admin_audit(admin_id,action,target_type,target_id) VALUES(?,?,?,?)');
        $query->execute([$row['id'], $input['action'] === 'complete' ? 'setup_complete' : 'setup_access_reissued', 'admin', $row['id']]);
        $row['password_hash'] = $hash;
        $row['auth_epoch'] = (string) ((int) $row['auth_epoch']+1);
    }
    $committing = true;
    $database->commit();
    echo json_encode(['status' => 'ok', 'administrator' => ['id' => (string) $row['id'],
        'email' => $row['email'], 'epoch' => (string) $row['auth_epoch'],
        'password_fingerprint' => hash('sha256', $row['password_hash'])]], JSON_THROW_ON_ERROR);
} catch (Throwable $error) {
    if (!$committing && $database instanceof PDO && $database->inTransaction()) {
        try { $database->rollBack(); } catch (Throwable) { $committing = true; }
    }
    echo json_encode(['status' => 'fail', 'uncertain' => $committing, 'class' => get_class($error),
        'reason' => $error instanceof RuntimeException ? $error->getMessage() : 'setup_database_failure'], JSON_THROW_ON_ERROR);
    exit(1);
}
