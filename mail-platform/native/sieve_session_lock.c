/* Copyright (c) 2026 MI-SYSTEM. SPDX-License-Identifier: MIT.
 * Serialize authenticated ManageSieve sessions across processes and generations.
 * Uses the public Dovecot mail-user hooks. No protocol or password interception.
 */
#include "lib.h"
#include "module-context.h"
#include "mail-user.h"
#include "mail-storage-hooks.h"
#include <fcntl.h>
#include <errno.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

const char *mail_sieve_session_lock_plugin_version = DOVECOT_ABI_VERSION;

struct session_lock_user {
    union mail_user_module_context module_ctx;
    int descriptor;
};

static MODULE_CONTEXT_DEFINE_INIT(session_lock_module, &mail_user_module_register);

static void session_lock_deinit(struct mail_user *user)
{
    struct session_lock_user *context = MODULE_CONTEXT(user, session_lock_module);
    int descriptor = context->descriptor;
    context->module_ctx.super.deinit(user);
    if (descriptor >= 0)
        (void)close(descriptor);
}

static int session_lock_open(struct mail_user *user)
{
    const char *home;
    const char *name = ".mail-settings-session.lock";
    struct stat parent, opened, named;
    int directory, descriptor;
    bool created;

    if (mail_user_get_home(user, &home) <= 0)
        return -1;
    directory = open(home, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (directory < 0)
        return -1;
    if (fstat(directory, &parent) < 0 || parent.st_uid != user->uid ||
        (parent.st_mode & 0022) != 0) {
        close(directory);
        return -1;
    }
    descriptor = openat(directory, name,
                        O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    created = descriptor >= 0;
    if (descriptor < 0 && errno == EEXIST)
        descriptor = openat(directory, name, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
    if (descriptor < 0) {
        close(directory);
        return -1;
    }
    if ((created && geteuid() == 0 && fchown(descriptor, user->uid, user->gid) < 0) ||
        fstat(descriptor, &opened) < 0 ||
        fstatat(directory, name, &named, AT_SYMLINK_NOFOLLOW) < 0 ||
        !S_ISREG(opened.st_mode) || !S_ISREG(named.st_mode) ||
        opened.st_uid != user->uid || (opened.st_mode & 0777) != 0600 ||
        opened.st_nlink != 1 || opened.st_ino != named.st_ino ||
        opened.st_dev != named.st_dev ||
        flock(descriptor, LOCK_EX | LOCK_NB) < 0) {
        close(descriptor);
        close(directory);
        return -1;
    }
    close(directory);
    return descriptor;
}

static void session_lock_created(struct mail_user *user)
{
    struct session_lock_user *context;
    struct mail_user_vfuncs *functions;
    int descriptor;

    e_debug(user->event, "Sieve session lock service=%s uid=%u effective_uid=%u",
            user->service, (unsigned int)user->uid, (unsigned int)geteuid());
    if (strcmp(user->service, "sieve") != 0)
        return;
    descriptor = session_lock_open(user);
    if (descriptor < 0) {
        user->error = p_strdup(user->pool, "settings_busy_or_lock_unavailable");
        return;
    }
    context = p_new(user->pool, struct session_lock_user, 1);
    context->descriptor = descriptor;
    functions = user->vlast;
    context->module_ctx.super = *functions;
    user->vlast = &context->module_ctx.super;
    functions->deinit = session_lock_deinit;
    MODULE_CONTEXT_SET(user, session_lock_module, context);
}

static const struct mail_storage_hooks session_lock_hooks = {
    .mail_user_created = session_lock_created,
};

void mail_sieve_session_lock_plugin_init(struct module *module)
{
    mail_storage_hooks_add(module, &session_lock_hooks);
}

void mail_sieve_session_lock_plugin_deinit(void)
{
    mail_storage_hooks_remove(&session_lock_hooks);
}
