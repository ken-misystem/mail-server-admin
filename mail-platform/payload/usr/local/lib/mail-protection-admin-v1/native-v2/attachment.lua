-- Managed extension decisions. CONFIG is rendered from typed administrator fields.
local config = __MAIL_ADMIN_CONFIG__
local blocked = {}
for _, extension in ipairs(config.extensions) do blocked[extension] = true end

local function blocked_name(name)
  if type(name) ~= 'string' then return false end
  local normalized = name:lower():gsub('[ .]+$', '')
  local extension = normalized:match('%.([a-z0-9]+)$')
  return extension ~= nil and blocked[extension] == true
end

local function inspect(task)
  local parts = task:get_parts() or {}
  if #parts > 1000 then error('managed_part_bound') end
  for _, part in ipairs(parts) do
    if blocked_name(part:get_filename()) then return true end
    if part:is_archive() then
      local archive = part:get_archive()
      if archive:is_encrypted() then
        if config.encrypted_archives then return true end
      elseif archive:is_unreadable() then
        error('managed_archive_unreadable')
      else
        local files = archive:get_files_full(1001)
        if #files > 1000 then error('managed_archive_bound') end
        for _, file in ipairs(files) do
          if config.encrypted_archives and file.encrypted then return true end
          if blocked_name(file.name) then return true end
        end
      end
    end
  end
  return false
end

local parent = rspamd_config:register_symbol({
  name = 'MAIL_ADMIN_ATTACHMENT_CHECK',
  type = 'postfilter',
  flags = 'explicit_disable,ignore_passthrough',
  priority = 10,
  callback = function(task)
    if #config.extensions == 0 and not config.encrypted_archives then return false end
    local ok, detected = pcall(inspect, task)
    local existing = task:get_metric_action()
    if not ok then
      task:insert_result('MAIL_ADMIN_ATTACHMENT_FAIL', 1.0)
      if existing ~= 'reject' then
        task:set_pre_result({action='soft reject', message='Temporary attachment inspection failure',
          module='mail_admin_protection', priority=2})
      end
      return false
    end
    if detected then
      task:insert_result('MAIL_ADMIN_ATTACHMENT', 1.0)
      if config.attachment_action == 'reject' then
        task:set_pre_result({action='reject', message='Attachment blocked by administrator policy',
          module='mail_admin_protection', priority=2})
      elseif existing ~= 'reject' and existing ~= 'soft reject' then
        task:set_pre_result({action='add header', message='Attachment flagged by administrator policy',
          module='mail_admin_protection', priority=2})
      end
    end
    return false
  end,
})
rspamd_config:register_symbol({name='MAIL_ADMIN_ATTACHMENT', type='virtual', score=0, parent=parent})
rspamd_config:register_symbol({name='MAIL_ADMIN_ATTACHMENT_FAIL', type='virtual', score=0, parent=parent})
