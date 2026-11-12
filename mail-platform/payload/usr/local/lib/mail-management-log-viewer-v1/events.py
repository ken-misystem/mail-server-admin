"""Pure bounded log normalization. No files, credentials, commands or DB access."""
import datetime as dt
import hashlib
import ipaddress
import json
import re

CATEGORIES=('smtp_in','smtp_out','delivery','access','filter','pop','web','security','system')
LEVELS=('info','warning','error')
UNITS=('postfix.service','dovecot.service','rspamd.service','nginx.service','php8.4-fpm.service',
       'fail2ban.service','mail-pop-general-dispatch.service','mail-pop-source@*.service',
       'mail-junk-digest-general.service','mail-management-operations.service')

def clip(text,bound):
    return text.encode('utf-8')[:bound].decode('utf-8','ignore')

def sanitize(value):
    """Preserve bounded reasons; remove authentication/header/HTTP payload and secret values."""
    text=str(value)
    if re.search(r'(?i)(?:\bAUTH\s+(?:PLAIN|LOGIN|XOAUTH2)\b|(?:^|[;\s])PASS\s+|-----BEGIN |\b(?:Subject|Received|Message-ID|DKIM-Signature)\s*[:=])',text):
        return '認証コマンド・鍵・メールヘッダーを含むため詳細を非表示'
    text=re.sub(r'^<[A-Za-z0-9_-]{8,128}>\s*','[session非表示] ',text)
    text=re.sub(r'(?i)\b(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+\S+\s+HTTP/[0-9.]+','HTTP request [URL非表示]',text)
    text=re.sub(r'(?i)\b(?:Authorization|Cookie|Set-Cookie)\s*[:=].*','[保護ヘッダー非表示]',text)
    text=re.sub(r'(?i)(?:https?|mysql|smtp|imap|pop3)://[^\s\x22\x27)]+','[URL非表示]',text)
    secret=r'(?:[A-Za-z0-9_-]*(?:password|passwd|passphrase|secret|api[_-]?key|token|credential|private[_-]?key|queue[_-]?key)[A-Za-z0-9_-]*|pwd|authorization|cookie|set-cookie|bearer|session(?:id|_id)?|challenge|recovery[_-]?code)'
    text=re.sub(r'(?i)([\x22\x27]?\b'+secret+r'[\x22\x27]?\s*[:=]\s*)(?:\x22(?:\\.|[^\x22\\])*\x22|\x27(?:\\.|[^\x27\\])*\x27|[^\s,;}]+)',r'\1[保護]',text)
    text=re.sub(r'(?i)\bBearer\s+\S+','Bearer [保護]',text)
    text=re.sub(r'\b[A-Za-z0-9+/_=-]{48,}\b','[長い識別値非表示]',text)
    text=re.sub(r'[^\S ]+',' ',text)
    text=''.join(c for c in text if c.isprintable())
    return clip(text,768)

def decode_json(raw):
    def unique(pairs):
        d={}
        for k,v in pairs:
            if k in d:raise ValueError('duplicate_json_key')
            d[k]=v
        return d
    return json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('json_constant')))

def event(row,now_us):
    if type(row)is not dict:raise ValueError('journal_record_shape')
    stamp=row.get('__REALTIME_TIMESTAMP');cursor=row.get('__CURSOR');message=row.get('MESSAGE')
    if not(type(stamp)is str and re.fullmatch(r'[0-9]{1,17}',stamp)and type(cursor)is str and 0<len(cursor)<=512):
        raise ValueError('journal_position_shape')
    stamp=int(stamp)
    if stamp<0 or stamp>now_us+300_000_000:raise ValueError('journal_timestamp')
    if type(message)is not str:return None # Binary MESSAGE is not rendered as text.
    if len(message.encode())>32768:return None
    unit=row.get('_SYSTEMD_UNIT','');source=row.get('SYSLOG_IDENTIFIER','')
    if type(source)is not str or type(unit)is not str:raise ValueError('journal_source_shape')
    if not re.fullmatch(r'[A-Za-z0-9_@./:-]{0,128}',source):source='unknown'
    if unit.startswith(('mail-pop-source@','mail-pop-general-dispatch')):category='pop'
    elif unit.startswith('mail-junk-digest-general'):category='filter'
    elif source.startswith('postfix/'):
        kind=source.rsplit('/',1)[-1]
        category='smtp_in'if kind in ('smtpd','postscreen','tlsproxy')else'smtp_out'if kind in ('smtp','lmtp')else'delivery'
    elif source.startswith('dovecot')or unit=='dovecot.service':category='access'
    elif source.startswith('rspamd')or unit=='rspamd.service':category='filter'
    elif source.startswith(('nginx','php-fpm','roundcube'))or unit in ('nginx.service','php8.4-fpm.service'):category='web'
    elif source.startswith('fail2ban')or unit=='fail2ban.service':category='security'
    else:category='system'
    priority=row.get('PRIORITY','6')
    if type(priority)is not str or re.fullmatch('[0-7]',priority)is None:raise ValueError('journal_priority_shape')
    if priority=='7':return None # Do not ingest debug streams or AUTH transcripts.
    level='error'if int(priority)<=3 else'warning'if int(priority)==4 else'info'
    outcome='event';lower=message.lower()
    # SMTP mentioned in a successful operation is NOT a warning.
    if re.search(r'\b(?:milter-reject|reject):',message):outcome='rejected';level='error'
    elif any(x in lower for x in ('authentication failed','auth failed','login failed')):outcome='auth_failed';level='warning'
    elif re.search(r'\b(?:fatal|panic|traceback|exception)\b',lower):outcome='failed';level='error'
    elif re.search(r'\bstatus=deferred\b',message):outcome='deferred';level='warning'
    elif re.search(r'\bstatus=(?:bounced|expired)\b',message):outcome='failed';level='error'
    elif re.search(r'\bstatus=sent\b',message):outcome='accepted';level='info'
    # Known worker JSON contains only public status metadata. Never retain its arbitrary fields.
    if category in ('pop','filter')and message.lstrip().startswith('{'):
        try:
            data=decode_json(message)
            if type(data)is dict:
                fields={k:data[k]for k in ('status','stage','phase','result','account_id','native_exit','error_class','reason')if k in data and type(data[k])in (str,int,bool,type(None))}
                diagnostic=data.get('diagnostic')
                if type(diagnostic)is dict:
                    fields.update({k:diagnostic[k]for k in ('native_exit_class','process_timed_out')if k in diagnostic and type(diagnostic[k])in (str,bool)})
                if fields:message=json.dumps(fields,ensure_ascii=False,separators=(',',':'))
                if data.get('status')in ('fail','failed','error'):level='error';outcome='failed'
        except (ValueError,TypeError):pass # Sanitized text remains available, never silently "success".
    def email(pattern):
        m=re.search(pattern,message,re.I)
        if not m:return ''
        value=m[1]
        return value if len(value)<=254 and re.fullmatch(r'[A-Za-z0-9.!#$%&*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+',value)else''
    sender=email(r'\bfrom=<([^<>]+)>');recipient=email(r'\bto=<([^<>]+)>')
    account=email(r'\b(?:user|username)=<?([^<> ,;]+)>?')
    ip=''
    m=re.search(r'\b(?:rip|client|ip)=([^ ,;]+)',message)
    if not m:m=re.search(r'\[([0-9a-fA-F:.]+)\]',message)
    if m:
        try:ip=str(ipaddress.ip_address(m[1]))
        except ValueError:pass
    queue='';m=re.match(r'([A-F0-9]{5,32}|[A-Za-z0-9]{10,32}): ',message)
    if m and m[1]!='NOQUEUE':queue=m[1]
    codes=re.findall(r'(?<![0-9])([245][0-9]{2}|[245]\.[0-9]\.[0-9]{1,3})(?![0-9])',message)
    return {'origin':hashlib.sha256(cursor.encode()).hexdigest(),'ts':stamp,'category':category,'level':level,
        'source':source or unit or'unknown','outcome':outcome,'text':sanitize(message),'sender':sender,'recipient':recipient,
        'account':account,'ip':ip,'queue':queue,'codes':list(dict.fromkeys(codes))[:6]}
