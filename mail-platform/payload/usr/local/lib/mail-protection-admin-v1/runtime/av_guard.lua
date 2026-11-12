-- Managed ClamAV INSTREAM guard. No cache, bypass or plaintext output.
local enabled = __ANTIVIRUS_ENABLED__
if not enabled then return end
local tcp = require 'rspamd_tcp'
local util = require 'rspamd_util'
local upstream = require 'rspamd_upstream_list'
local servers = upstream.create(rspamd_config, '__CLAMAV_SOCKET__', 3310)
assert(servers, 'managed_clamav_endpoint')
local function verdict(task, infected, failure)
  if infected then
    task:insert_result('MAIL_ADMIN_VIRUS', 1.0)
    task:set_pre_result({action='reject', message='Malware blocked by administrator policy',
      module='mail_admin_antivirus', priority=3})
  elseif failure then
    task:insert_result('MAIL_ADMIN_VIRUS_FAIL', 1.0)
    if task:get_metric_action() ~= 'reject' then
      task:set_pre_result({action='soft reject', message='Temporary antivirus inspection failure',
        module='mail_admin_antivirus', priority=3})
    end
  end
end
local parent = rspamd_config:register_symbol({
  name='MAIL_ADMIN_AV_GUARD', type='postfilter', priority=20,
  flags='explicit_disable,ignore_passthrough',
  callback=function(task)
    local content = task:get_content()
    if not content or #content > 10485760 then verdict(task, false, true); return false end
    local target = servers:get_upstream_round_robin()
    if not target then verdict(task, false, true); return false end
    local address = target:get_addr()
    local completed = false
    local function finish(infected, failed)
      if not completed then completed=true; verdict(task, infected, failed) end
    end
    local scheduled = tcp.request({
      task=task, host=address:to_string(), port=address:get_port(), upstream=target,
      timeout=10, stop_pattern='\0',
      data={util.pack("c9 c1 >I4", "zINSTREAM", "\0", #content), content, util.pack(">I4", 0)},
      callback=function(err, data)
        if err or not data then finish(false, true); return end
        local reply = tostring(data):gsub('%z$', '')
        if reply == 'stream: OK' then finish(false, false)
        elseif reply:match('^stream: .+ FOUND$') then finish(true, false)
        else finish(false, true) end
      end,
    })
    if not scheduled then finish(false, true) end
    return false
  end,
})
rspamd_config:register_symbol({name='MAIL_ADMIN_VIRUS', type='virtual', score=0, parent=parent})
rspamd_config:register_symbol({name='MAIL_ADMIN_VIRUS_FAIL', type='virtual', score=0, parent=parent})
