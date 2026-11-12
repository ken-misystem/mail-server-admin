/* Fixed same-origin POST adapter. No retry, URL secret, external endpoint or storage. */
"use strict";
(function(root){
  const OPS=new Set(['list','issue_options','issue_finish','revoke_options','revoke_finish','download']);
  const check=(value,code)=>{if(!value)throw new Error(code);};
  function decode(value){check(typeof value==='string'&&/^[A-Za-z0-9_-]{1,4096}$/.test(value),'webauthn_binary');
    const s=value.replace(/-/g,'+').replace(/_/g,'/');return Uint8Array.from(root.atob(s+'='.repeat((4-s.length%4)%4)),c=>c.charCodeAt(0)).buffer;}
  function encode(value){return root.btoa(String.fromCharCode(...new Uint8Array(value))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');}
  async function bounded(response,maximum){
    check(response.body&&response.body.getReader,'response_stream_required');const reader=response.body.getReader();const chunks=[];let size=0;
    try{while(true){const part=await reader.read();if(part.done)break;size+=part.value.byteLength;check(size<=maximum,'response_bound');chunks.push(part.value);}}
    finally{await reader.cancel().catch(()=>{});reader.releaseLock();}
    const result=new Uint8Array(size);let position=0;for(const c of chunks){result.set(c,position);position+=c.byteLength;}return result;
  }
  class Transport{
    constructor(rc,fetcher=root.fetch.bind(root)){this.rc=rc;this.fetcher=fetcher;}
    async request(operation,body){
      check(OPS.has(operation),'fixed_certificate_operation');check(typeof this.rc.env.request_token==='string'&&this.rc.env.request_token.length>=16,'csrf_token_missing');
      const url=new URL(this.rc.url('plugin.mail_client_certificates-'+operation),root.location.href);
      check(url.origin===root.location.origin&&!url.username&&!url.password,'same_origin_required');
      const controller=new AbortController();const timer=setTimeout(()=>controller.abort(),operation==='issue_finish'?230000:30000);
      try{const response=await this.fetcher(url.href,{method:'POST',credentials:'same-origin',redirect:'error',cache:'no-store',signal:controller.signal,
        headers:{'Content-Type':'application/json','X-Roundcube-Request':this.rc.env.request_token},body:JSON.stringify(body)});
        return {response,close:()=>clearTimeout(timer)};}
      catch(error){clearTimeout(timer);throw error;}
    }
    async post(operation,body){
      check(operation!=='download','binary_route_required');const lease=await this.request(operation,body);
      try{const response=lease.response;check(response.ok&&/application\/json\b/i.test(response.headers.get('Content-Type')||''),'operation_unverified');
        const result=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(await bounded(response,65536)));
        check(result&&typeof result==='object'&&!Array.isArray(result)&&result.ok!==false,'operation_unverified');return result;}
      finally{lease.close();}
    }
    async readiness(){return root.MailOwnerPrerequisites.read(this.rc,this.fetcher);}
    async assert(input){
      check(input&&input.userVerification==='required','fresh_uv_required');
      const publicKey={...input,challenge:decode(input.challenge),allowCredentials:(input.allowCredentials||[]).map(c=>({...c,id:decode(c.id)}))};
      const credential=await root.navigator.credentials.get({publicKey});check(credential&&credential.type==='public-key','assertion_cancelled');
      return {id:credential.id,rawId:encode(credential.rawId),type:credential.type,authenticatorAttachment:credential.authenticatorAttachment||null,
        clientExtensionResults:credential.getClientExtensionResults(),response:{clientDataJSON:encode(credential.response.clientDataJSON),
          authenticatorData:encode(credential.response.authenticatorData),signature:encode(credential.response.signature),
          userHandle:credential.response.userHandle?encode(credential.response.userHandle):null}};
    }
    async downloadPost(ticket){
      check(ticket&&typeof ticket.device_id==='string'&&typeof ticket.download_handle==='string','p12_request_invalid');
      // Expiry is UI metadata, not an allowed download API input. Keep the strict server contract.
      const lease=await this.request('download',{device_id:ticket.device_id,download_handle:ticket.download_handle});let raw=null;
      try{const response=lease.response;
        if(!response.ok||!/^application\/x-pkcs12(?:;|$)/i.test(response.headers.get('Content-Type')||'')){
          let code='p12_response_unverified';
          if(/^application\/json(?:;|$)/i.test(response.headers.get('Content-Type')||'')){
            const failure=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(await bounded(response,65536)));
            if(failure?.error_code==='input_invalid')code='p12_request_rejected';
          }
          throw new Error(code);
        }
        raw=await bounded(response,131072);const length=Number(response.headers.get('Content-Length'));
        check(Number.isInteger(length)&&length>0&&length===raw.byteLength,'p12_length_unverified');
        const url=root.URL.createObjectURL(new Blob([raw],{type:'application/x-pkcs12'}));const a=root.document.createElement('a');
        try{a.href=url;a.download='mail-device.p12';a.hidden=true;root.document.body.append(a);a.click();}
        finally{a.remove();setTimeout(()=>root.URL.revokeObjectURL(url),1000);}}
      finally{lease.close();if(raw)raw.fill(0);}
    }
  }
  if(typeof module!=='undefined')module.exports={Transport,decode,encode,bounded};
  if(root.rcmail)root.rcmail.addEventListener('init',()=>{
    if(!root.rcmail.env.mail_client_certificates_ready)return;const panel=root.document.querySelector('.device-certificates');
    if(panel){const ui=new root.DeviceCertificatesUI(panel,new Transport(root.rcmail));ui.operation(()=>ui.list());}
  });
})(typeof window!=='undefined'?window:globalThis);
